from unittest.mock import MagicMock

from secval.code_processing.code_models import CodeChunk
from secval.hybrid_search.open_search_storage import (
    CODE_INDEX_NAME,
    code_chunk_to_document,
    save_code_chunk,
)
from secval.shared_types import (
    ChunkId,
    FileId,
    RepositoryId,
    SnapshotId,
    SymbolId,
)


def create_example_code_chunk() -> CodeChunk:
    """创建多个测试都会使用的代码块。"""

    return CodeChunk(
        chunk_id=ChunkId("chunk-1"),
        file_id=FileId("file-1"),
        repository_id=RepositoryId("repository-1"),
        snapshot_id=SnapshotId("snapshot-1"),
        relative_path="src/UserService.java",
        language="java",
        chunk_type="method",
        content="public User findUser() { return user; }",
        start_line=10,
        end_line=12,
        symbol_id=SymbolId("symbol-1"),
        symbol_name="findUser",
    )


def test_convert_code_chunk_to_document() -> None:
    code_chunk = create_example_code_chunk()

    document = code_chunk_to_document(code_chunk)

    assert document == {
        "chunk_id": "chunk-1",
        "file_id": "file-1",
        "repository_id": "repository-1",
        "snapshot_id": "snapshot-1",
        "relative_path": "src/UserService.java",
        "language": "java",
        "chunk_type": "method",
        "content": "public User findUser() { return user; }",
        "search_text": (
            "finduser find user public user finduser find user return user"
        ),
        "start_line": 10,
        "end_line": 12,
        "symbol_id": "symbol-1",
        "symbol_name": "findUser",
    }


def test_save_code_chunk_uses_chunk_id_as_document_id() -> None:
    connection = MagicMock()
    code_chunk = create_example_code_chunk()

    save_code_chunk(connection, code_chunk)

    connection.index.assert_called_once_with(
        index=CODE_INDEX_NAME,
        id="chunk-1",
        body=code_chunk_to_document(code_chunk),
    )
