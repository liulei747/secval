"""把 OpenSearch 文档还原成代码块。"""

from typing import Any

from opensearchpy import OpenSearch

from secval.infrastructure.opensearch.code_index import CODE_INDEX_NAME
from secval.models.code import CodeChunk
from secval.shared_types import (
    ChunkId,
    FileId,
    RepositoryId,
    SnapshotId,
    SymbolId,
)


def document_to_code_chunk(document: dict[str, Any]) -> CodeChunk:
    """把 OpenSearch 返回的普通字典转换成 CodeChunk。"""

    symbol_id_value = document.get("symbol_id")
    symbol_ids = [SymbolId(value) for value in document.get("symbol_ids", [])]
    symbol_id = None

    if symbol_id_value is not None:
        symbol_id = SymbolId(symbol_id_value)

    return CodeChunk(
        chunk_id=ChunkId(document["chunk_id"]),
        file_id=FileId(document["file_id"]),
        repository_id=RepositoryId(document["repository_id"]),
        snapshot_id=SnapshotId(document["snapshot_id"]),
        relative_path=document["relative_path"],
        language=document["language"],
        chunk_type=document["chunk_type"],
        content=document["content"],
        start_line=document["start_line"],
        end_line=document["end_line"],
        symbol_id=symbol_id,
        symbol_name=document.get("symbol_name"),
        symbol_ids=symbol_ids,
        symbol_names=list(document.get("symbol_names", [])),
    )


def load_code_chunks_by_ids(
    connection: OpenSearch,
    chunk_ids: list[ChunkId],
) -> list[CodeChunk]:
    """按输入 ID 的顺序批量读取完整代码块。"""

    if len(chunk_ids) == 0:
        return []

    response = connection.mget(
        index=CODE_INDEX_NAME,
        body={"ids": [str(chunk_id) for chunk_id in chunk_ids]},
    )
    chunks_by_id: dict[str, CodeChunk] = {}

    for document in response["docs"]:
        if not document.get("found", False):
            continue

        code_chunk = document_to_code_chunk(document["_source"])
        chunks_by_id[str(code_chunk.chunk_id)] = code_chunk

    ordered_chunks: list[CodeChunk] = []

    for chunk_id in chunk_ids:
        code_chunk = chunks_by_id.get(str(chunk_id))

        if code_chunk is None:
            raise ValueError(f"找不到向量对应的代码块：{chunk_id}")

        ordered_chunks.append(code_chunk)

    return ordered_chunks
