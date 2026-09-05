"""处理代码仓库并建立关键词搜索索引。"""

import logging
from pathlib import Path
from uuid import uuid4

from opensearchpy import OpenSearch
from qdrant_client import QdrantClient

from secval.code_processing.repository_processing import process_repository
from secval.infrastructure.opensearch.code_index import create_code_index
from secval.infrastructure.opensearch.delete_old_code_chunks import (
    delete_code_chunks_by_run,
    delete_old_code_chunks,
)
from secval.infrastructure.opensearch.save_code_chunks import (
    save_code_chunks,
)
from secval.infrastructure.qdrant import (
    create_code_vector_collection,
    delete_code_vectors_by_run,
    delete_old_code_vectors,
    save_code_vectors,
)
from secval.interfaces import EmbeddingModel
from secval.interfaces.audit import SourceSnapshotPort
from secval.models.code import (
    CodeChunk,
    CodeRepository,
    CodeSnapshot,
    require_unique_chunk_ids,
)
from secval.services.repository_index_result import (
    RepositoryIndexResult,
)

logger = logging.getLogger(__name__)


def index_repository(
    open_search_connection: OpenSearch,
    qdrant_client: QdrantClient,
    embedding_model: EmbeddingModel,
    repository: CodeRepository,
    snapshot: CodeSnapshot,
    source_store: SourceSnapshotPort | None = None,
    graph_store=None,
    joern_client=None,
    joern_shared_root="/joern-inputs",
    progress=None,
) -> RepositoryIndexResult:
    """扫描固定源码，并写入搜索、关系和路径分析存储。"""

    if snapshot.repository_id != repository.repository_id:
        raise ValueError("代码版本不属于当前仓库")

    _report_progress(progress, "准备搜索存储")
    index_created = create_code_index(open_search_connection)
    vector_collection_created = create_code_vector_collection(qdrant_client)

    source_snapshot_id = None
    old_index_runs = []
    if source_store is not None:
        _report_progress(progress, "固定源码快照")
        old_index_runs = source_store.list_bound_runs(repository.repository_id, snapshot.snapshot_id)
        source_snapshot_id = source_store.capture(
            Path(repository.root_path), repository.repository_id, snapshot.version,
        )
        with source_store.indexing_directory(source_snapshot_id) as root:
            _report_progress(progress, "解析并切分代码")
            process_result = process_repository(
                root_path=root, repository_id=repository.repository_id,
                snapshot_id=snapshot.snapshot_id,
            )
    else:
        _report_progress(progress, "解析并切分代码")
        process_result = process_repository(
            root_path=repository.root_path,
            repository_id=repository.repository_id,
            snapshot_id=snapshot.snapshot_id,
        )

    if process_result.errors:
        error_summary = "; ".join(
            f"{error.relative_path}: {error.message}"
            for error in process_result.errors[:5]
        )
        raise ValueError(
            "仓库包含无法处理的文件，本次索引未替换："
            f"{error_summary}"
        )

    require_unique_chunk_ids(process_result.chunks)

    index_run_id = str(uuid4())
    _report_progress(progress, "生成代码向量")
    embedding_texts = _create_embedding_texts(process_result.chunks)
    vectors = embedding_model.embed_code(embedding_texts)

    try:
        _report_progress(progress, "写入OpenSearch")
        saved_chunks = save_code_chunks(
            connection=open_search_connection,
            code_chunks=process_result.chunks,
            index_run_id=index_run_id,
        )
        _report_progress(progress, "写入Qdrant")
        saved_vectors = save_code_vectors(
            client=qdrant_client,
            code_chunks=process_result.chunks,
            vectors=vectors,
            index_run_id=index_run_id,
        )
        if saved_chunks != len(process_result.chunks) or saved_vectors != len(process_result.chunks):
            raise ValueError("索引写入数量不完整，本批次不能绑定源码快照")
        if graph_store is not None:
            _report_progress(progress, "写入Neo4j")
            graph_store.save_snapshot(repository.repository_id, snapshot.snapshot_id,
                                      index_run_id, process_result.chunks)
        if joern_client is not None:
            _report_progress(progress, "生成Joern路径图")
            if source_store is None or source_snapshot_id is None:
                raise ValueError("Joern索引必须使用固定源码快照")
            languages = sorted({chunk.language for chunk in process_result.chunks})
            for language in languages:
                with source_store.joern_directory(
                    source_snapshot_id, joern_shared_root, language
                ) as directory:
                    joern_client.import_code(directory, index_run_id, language)
        if source_store is not None and source_snapshot_id is not None:
            _report_progress(progress, "绑定新索引与源码")
            source_store.bind(source_snapshot_id, repository.repository_id,
                              snapshot.snapshot_id, index_run_id)
    except Exception:
        # 多个存储没有跨库事务；失败时尽最大努力清掉本批次残留。
        try:
            delete_code_chunks_by_run(open_search_connection, index_run_id)
        except Exception:
            logger.exception("回滚 OpenSearch 索引批次失败：%s", index_run_id)
        try:
            delete_code_vectors_by_run(qdrant_client, index_run_id)
        except Exception:
            logger.exception("回滚 Qdrant 索引批次失败：%s", index_run_id)
        if graph_store is not None:
            try:
                graph_store.delete_run(repository.repository_id, snapshot.snapshot_id, index_run_id)
            except Exception:
                logger.exception("回滚 Neo4j 索引批次失败：%s", index_run_id)
        if joern_client is not None:
            try:
                joern_client.delete_project(index_run_id)
            except Exception:
                logger.exception("回滚 Joern 索引批次失败：%s", index_run_id)
        raise

    # 只有全部新数据和源码绑定成功后，才开始清理旧批次。
    _report_progress(progress, "清理旧索引")
    deleted_chunks = delete_old_code_chunks(
        connection=open_search_connection,
        repository_id=repository.repository_id,
        snapshot_id=snapshot.snapshot_id,
        current_index_run_id=index_run_id,
    )
    delete_old_code_vectors(
        client=qdrant_client,
        repository_id=repository.repository_id,
        snapshot_id=snapshot.snapshot_id,
        current_index_run_id=index_run_id,
    )
    if graph_store is not None:
        try:
            graph_store.delete_old_runs(repository.repository_id, snapshot.snapshot_id, index_run_id)
        except Exception:
            # 新批次已经完整可用；旧图残留不应把成功导入报告成失败。
            logger.exception("清理 Neo4j 旧索引批次失败：%s", index_run_id)

    if joern_client is not None:
        for old_run in old_index_runs:
            if old_run == index_run_id:
                continue
            try:
                joern_client.delete_project(old_run)
            except Exception:
                # 新项目及源码绑定已经完成；旧项目残留只记录，不回滚新结果。
                logger.exception("清理 Joern 旧索引批次失败：%s", old_run)

    return RepositoryIndexResult(
        process_result=process_result,
        deleted_chunks=deleted_chunks,
        saved_chunks=saved_chunks,
        saved_vectors=saved_vectors,
        index_created=index_created,
        vector_collection_created=vector_collection_created,
        index_run_id=index_run_id,
    )


def _create_embedding_texts(code_chunks: list[CodeChunk]) -> list[str]:
    """组合路径、符号名称和代码正文，供 Embedding 模型理解。"""

    embedding_texts: list[str] = []

    for code_chunk in code_chunks:
        text_parts = [
            f"File: {code_chunk.relative_path}",
            f"Language: {code_chunk.language}",
        ]

        if code_chunk.symbol_name is not None:
            text_parts.append(f"Symbol: {code_chunk.symbol_name}")

        text_parts.append("Code:")
        text_parts.append(code_chunk.content)
        embedding_texts.append("\n".join(text_parts))

    return embedding_texts


def _report_progress(progress, stage):
    """向Web后台任务报告当前阶段；命令行或单元测试可以不传。"""
    if progress is not None:
        progress(stage)
