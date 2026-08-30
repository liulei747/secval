from unittest.mock import MagicMock

from secval.hybrid_search.open_search_storage import (
    CODE_INDEX_NAME,
    load_code_chunks_by_ids,
)
from secval.shared_types import ChunkId


def create_document(chunk_id: str) -> dict:
    """创建 OpenSearch mget 返回的测试文档。"""

    return {
        "found": True,
        "_source": {
            "chunk_id": chunk_id,
            "file_id": "file-1",
            "repository_id": "repository-1",
            "snapshot_id": "snapshot-1",
            "relative_path": "src/UserService.java",
            "language": "java",
            "chunk_type": "method",
            "content": f"void {chunk_id}() {{}}",
            "start_line": 1,
            "end_line": 1,
            "symbol_id": None,
            "symbol_name": chunk_id,
        },
    }


def test_load_chunks_in_requested_rank_order() -> None:
    connection = MagicMock()
    connection.mget.return_value = {
        "docs": [
            create_document("chunk-1"),
            create_document("chunk-2"),
        ]
    }

    chunks = load_code_chunks_by_ids(
        connection,
        [ChunkId("chunk-2"), ChunkId("chunk-1")],
    )

    connection.mget.assert_called_once_with(
        index=CODE_INDEX_NAME,
        body={"ids": ["chunk-2", "chunk-1"]},
    )
    assert [chunk.chunk_id for chunk in chunks] == [
        "chunk-2",
        "chunk-1",
    ]
