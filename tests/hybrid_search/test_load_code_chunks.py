from unittest.mock import MagicMock

from secval.infrastructure.opensearch import (
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


def test_load_shared_field_chunk_keeps_all_symbol_references() -> None:
    connection = MagicMock()
    document = create_document("chunk-fields")
    document["_source"].update(
        {
            "chunk_type": "field",
            "symbol_id": None,
            "symbol_name": "A.first, A.second",
            "symbol_ids": ["symbol-first", "symbol-second"],
            "symbol_names": ["A.first", "A.second"],
        }
    )
    connection.mget.return_value = {"docs": [document]}

    chunks = load_code_chunks_by_ids(
        connection,
        [ChunkId("chunk-fields")],
    )

    assert chunks[0].symbol_id is None
    assert chunks[0].symbol_ids == ["symbol-first", "symbol-second"]
    assert chunks[0].symbol_names == ["A.first", "A.second"]
