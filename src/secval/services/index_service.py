"""处理代码仓库并建立关键词搜索索引。"""

import logging
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
) -> RepositoryIndexResult:
    """扫描仓库，并把代码块和向量写入两个搜索存储。"""

    if snapshot.repository_id != repository.repository_id:
        raise ValueError("代码版本不属于当前仓库")

    index_created = create_code_index(open_search_connection)
    vector_collection_created = create_code_vector_collection(qdrant_client)

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
    embedding_texts = _create_embedding_texts(process_result.chunks)
    vectors = embedding_model.embed_code(embedding_texts)

    try:
        saved_chunks = save_code_chunks(
            connection=open_search_connection,
            code_chunks=process_result.chunks,
            index_run_id=index_run_id,
        )
        saved_vectors = save_code_vectors(
            client=qdrant_client,
            code_chunks=process_result.chunks,
            vectors=vectors,
            index_run_id=index_run_id,
        )
    except Exception:
        # 两个存储没有跨库事务；失败时尽最大努力清掉本批次残留。
        try:
            delete_code_chunks_by_run(open_search_connection, index_run_id)
        except Exception:
            logger.exception("回滚 OpenSearch 索引批次失败：%s", index_run_id)
        try:
            delete_code_vectors_by_run(qdrant_client, index_run_id)
        except Exception:
            logger.exception("回滚 Qdrant 索引批次失败：%s", index_run_id)
        raise

    # 只有两个存储的新数据全部写入成功后，才开始清理旧批次。
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
