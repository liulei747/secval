from unittest.mock import MagicMock, patch

import pytest

from secval.code_processing.code_models import CodeChunk
from secval.hybrid_search.open_search_storage import (
    CODE_INDEX_NAME,
    save_code_chunks,
)
from secval.shared_types import ChunkId, FileId, RepositoryId, SnapshotId


def create_code_chunk(chunk_number: int) -> CodeChunk:
    """创建具有不同 ID 的测试代码块。"""

    return CodeChunk(
        chunk_id=ChunkId(f"chunk-{chunk_number}"),
        file_id=FileId("file-1"),
        repository_id=RepositoryId("repository-1"),
        snapshot_id=SnapshotId("snapshot-1"),
        relative_path="src/UserService.java",
        language="java",
        chunk_type="method",
        content=f"void method{chunk_number}() {{}}",
        start_line=chunk_number,
        end_line=chunk_number,
    )


@patch(
    "secval.hybrid_search.open_search_storage.save_code_chunks.bulk"
)
def test_save_multiple_code_chunks(mock_bulk: MagicMock) -> None:
    connection = MagicMock()
    code_chunks = [create_code_chunk(1), create_code_chunk(2)]
    mock_bulk.return_value = (2, [])

    saved_count = save_code_chunks(
        connection,
        code_chunks,
        index_run_id="run-1",
    )

    assert saved_count == 2

    actions = mock_bulk.call_args.args[1]
    assert mock_bulk.call_args.kwargs["refresh"] == "wait_for"
    assert len(actions) == 2
    assert actions[0]["_index"] == CODE_INDEX_NAME
    assert actions[0]["_id"] == "chunk-1"
    assert actions[0]["_source"]["content"] == "void method1() {}"
    assert actions[0]["_source"]["index_run_id"] == "run-1"
    assert actions[1]["_id"] == "chunk-2"


@patch(
    "secval.hybrid_search.open_search_storage.save_code_chunks.bulk"
)
def test_do_not_request_open_search_for_empty_list(
    mock_bulk: MagicMock,
) -> None:
    connection = MagicMock()

    saved_count = save_code_chunks(connection, [], index_run_id="run-1")

    assert saved_count == 0
    mock_bulk.assert_not_called()


@patch(
    "secval.hybrid_search.open_search_storage.save_code_chunks.bulk"
)
def test_reject_duplicate_chunk_ids_before_open_search_write(
    mock_bulk: MagicMock,
) -> None:
    duplicate_chunks = [create_code_chunk(1), create_code_chunk(1)]

    with pytest.raises(ValueError, match="代码块 ID 不能重复"):
        save_code_chunks(
            MagicMock(),
            duplicate_chunks,
            index_run_id="run-1",
        )

    mock_bulk.assert_not_called()
