"""把代码块保存到 OpenSearch。"""

from typing import Any

from opensearchpy import OpenSearch

from secval.code_processing.code_models import CodeChunk
from secval.hybrid_search.open_search_storage.code_index import CODE_INDEX_NAME


def code_chunk_to_document(code_chunk: CodeChunk) -> dict[str, Any]:
    """把 CodeChunk 转换成 OpenSearch 可以保存的普通字典。"""

    return {
        "chunk_id": code_chunk.chunk_id,
        "file_id": code_chunk.file_id,
        "repository_id": code_chunk.repository_id,
        "snapshot_id": code_chunk.snapshot_id,
        "relative_path": code_chunk.relative_path,
        "language": code_chunk.language,
        "chunk_type": code_chunk.chunk_type,
        "content": code_chunk.content,
        "start_line": code_chunk.start_line,
        "end_line": code_chunk.end_line,
        "symbol_id": code_chunk.symbol_id,
        "symbol_name": code_chunk.symbol_name,
    }


def save_code_chunk(
    connection: OpenSearch,
    code_chunk: CodeChunk,
) -> None:
    """把一个代码块写入代码索引。

    使用 chunk_id 作为 OpenSearch 文档 ID。
    相同代码块再次写入时会更新原文档，不会产生重复文档。
    """

    document = code_chunk_to_document(code_chunk)

    connection.index(
        index=CODE_INDEX_NAME,
        id=str(code_chunk.chunk_id),
        body=document,
    )
