from unittest.mock import MagicMock, patch

import pytest

from secval.infrastructure.embedding import EMBEDDING_DIMENSION
from secval.models.code import (
    CodeChunk,
    CodeRepository,
    CodeSnapshot,
    FileProcessError,
    RepositoryProcessResult,
)
from secval.services import index_repository
from secval.shared_types import (
    ChunkId,
    FileId,
    RepositoryId,
    SnapshotId,
)

DEFAULT_REPOSITORY_ID = RepositoryId("repository-1")


def create_repository() -> CodeRepository:
    """创建测试使用的仓库。"""

    return CodeRepository(
        repository_id=RepositoryId("repository-1"),
        name="example",
        root_path="C:/code/example",
    )


def create_snapshot(
    repository_id: RepositoryId = DEFAULT_REPOSITORY_ID,
) -> CodeSnapshot:
    """创建测试使用的代码版本。"""

    return CodeSnapshot(
        snapshot_id=SnapshotId("snapshot-1"),
        repository_id=repository_id,
        version="commit-1",
    )


def create_process_result() -> RepositoryProcessResult:
    """创建包含一个代码块的仓库处理结果。"""

    code_chunk = CodeChunk(
        chunk_id=ChunkId("chunk-1"),
        file_id=FileId("file-1"),
        repository_id=RepositoryId("repository-1"),
        snapshot_id=SnapshotId("snapshot-1"),
        relative_path="src/UserService.java",
        language="java",
        chunk_type="method",
        content="void findUser() {}",
        start_line=1,
        end_line=1,
        symbol_name="UserService.findUser()",
    )

    return RepositoryProcessResult(
        total_files=1,
        successful_files=1,
        chunks=[code_chunk],
        errors=[],
    )


@patch("secval.services.index_service.delete_old_code_vectors")
@patch("secval.services.index_service.delete_old_code_chunks")
@patch("secval.services.index_service.save_code_vectors")
@patch("secval.services.index_service.save_code_chunks")
@patch("secval.services.index_service.create_code_vector_collection")
@patch("secval.services.index_service.process_repository")
@patch("secval.services.index_service.create_code_index")
def test_index_repository_runs_the_complete_flow(
    mock_create_code_index: MagicMock,
    mock_process_repository: MagicMock,
    mock_create_vector_collection: MagicMock,
    mock_save_code_chunks: MagicMock,
    mock_save_code_vectors: MagicMock,
    mock_delete_old_chunks: MagicMock,
    mock_delete_old_vectors: MagicMock,
) -> None:
    open_search = MagicMock()
    qdrant = MagicMock()
    embedding_model = MagicMock()
    process_result = create_process_result()
    vector = [0.0] * EMBEDDING_DIMENSION
    call_order: list[str] = []
    mock_create_code_index.return_value = True
    mock_create_vector_collection.return_value = True
    mock_process_repository.return_value = process_result
    embedding_model.embed_code.return_value = [vector]
    mock_save_code_chunks.side_effect = lambda **kwargs: (
        call_order.append("save_chunks") or 1
    )
    mock_save_code_vectors.side_effect = lambda **kwargs: (
        call_order.append("save_vectors") or 1
    )
    mock_delete_old_chunks.side_effect = lambda **kwargs: (
        call_order.append("delete_chunks") or 3
    )
    mock_delete_old_vectors.side_effect = lambda **kwargs: (
        call_order.append("delete_vectors")
    )

    result = index_repository(
        open_search_connection=open_search,
        qdrant_client=qdrant,
        embedding_model=embedding_model,
        repository=create_repository(),
        snapshot=create_snapshot(),
    )

    mock_create_code_index.assert_called_once_with(open_search)
    mock_create_vector_collection.assert_called_once_with(qdrant)
    embedding_text = embedding_model.embed_code.call_args.args[0][0]
    assert "File: src/UserService.java" in embedding_text
    assert "Symbol: UserService.findUser()" in embedding_text
    assert "Code:\nvoid findUser() {}" in embedding_text

    index_run_id = mock_save_code_chunks.call_args.kwargs["index_run_id"]
    mock_save_code_vectors.assert_called_once_with(
        client=qdrant,
        code_chunks=process_result.chunks,
        vectors=[vector],
        index_run_id=index_run_id,
    )
    mock_delete_old_chunks.assert_called_once_with(
        connection=open_search,
        repository_id=RepositoryId("repository-1"),
        snapshot_id=SnapshotId("snapshot-1"),
        current_index_run_id=index_run_id,
    )
    mock_delete_old_vectors.assert_called_once_with(
        client=qdrant,
        repository_id=RepositoryId("repository-1"),
        snapshot_id=SnapshotId("snapshot-1"),
        current_index_run_id=index_run_id,
    )
    assert call_order == [
        "save_chunks",
        "save_vectors",
        "delete_chunks",
        "delete_vectors",
    ]
    assert result.saved_chunks == 1
    assert result.saved_vectors == 1
    assert result.deleted_chunks == 3
    assert result.index_created is True
    assert result.vector_collection_created is True
    assert result.index_run_id == index_run_id


@patch("secval.services.index_service.create_code_index")
def test_reject_snapshot_from_another_repository(
    mock_create_code_index: MagicMock,
) -> None:
    with pytest.raises(ValueError, match="代码版本不属于当前仓库"):
        index_repository(
            open_search_connection=MagicMock(),
            qdrant_client=MagicMock(),
            embedding_model=MagicMock(),
            repository=create_repository(),
            snapshot=create_snapshot(RepositoryId("repository-2")),
        )

    mock_create_code_index.assert_not_called()


def test_do_not_delete_old_data_when_vector_save_fails() -> None:
    process_result = create_process_result()
    embedding_model = MagicMock()
    embedding_model.embed_code.return_value = [[0.0] * EMBEDDING_DIMENSION]

    with patch(
        "secval.services.index_service.create_code_index",
        return_value=False,
    ), patch(
        "secval.services.index_service.create_code_vector_collection",
        return_value=False,
    ), patch(
        "secval.services.index_service.process_repository",
        return_value=process_result,
    ), patch(
        "secval.services.index_service.save_code_chunks",
        return_value=1,
    ), patch(
        "secval.services.index_service.save_code_vectors",
        side_effect=RuntimeError("向量写入失败"),
    ), patch(
        "secval.services.index_service.delete_old_code_chunks"
    ) as mock_delete_chunks, patch(
        "secval.services.index_service.delete_old_code_vectors"
    ) as mock_delete_vectors, pytest.raises(
        RuntimeError,
        match="向量写入失败",
    ):
        index_repository(
            open_search_connection=MagicMock(),
            qdrant_client=MagicMock(),
            embedding_model=embedding_model,
            repository=create_repository(),
            snapshot=create_snapshot(),
        )

    mock_delete_chunks.assert_not_called()
    mock_delete_vectors.assert_not_called()


def test_do_not_replace_old_index_when_any_source_file_fails() -> None:
    process_result = RepositoryProcessResult(
        total_files=2,
        successful_files=1,
        chunks=create_process_result().chunks,
        errors=[
            FileProcessError(
                relative_path="Broken.java",
                message="Java 文件存在语法错误",
            )
        ],
    )
    embedding_model = MagicMock()

    with patch(
        "secval.services.index_service.create_code_index",
        return_value=False,
    ), patch(
        "secval.services.index_service.create_code_vector_collection",
        return_value=False,
    ), patch(
        "secval.services.index_service.process_repository",
        return_value=process_result,
    ), patch(
        "secval.services.index_service.save_code_chunks"
    ) as mock_save_chunks, patch(
        "secval.services.index_service.save_code_vectors"
    ) as mock_save_vectors, patch(
        "secval.services.index_service.delete_old_code_chunks"
    ) as mock_delete_chunks, patch(
        "secval.services.index_service.delete_old_code_vectors"
    ) as mock_delete_vectors, pytest.raises(
        ValueError,
        match="本次索引未替换",
    ):
        index_repository(
            open_search_connection=MagicMock(),
            qdrant_client=MagicMock(),
            embedding_model=embedding_model,
            repository=create_repository(),
            snapshot=create_snapshot(),
        )

    embedding_model.embed_code.assert_not_called()
    mock_save_chunks.assert_not_called()
    mock_save_vectors.assert_not_called()
    mock_delete_chunks.assert_not_called()
    mock_delete_vectors.assert_not_called()
