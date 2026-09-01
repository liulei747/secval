from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest
from qdrant_client.http import models

from secval.code_processing.code_models import CodeChunk
from secval.hybrid_search.local_embedding import EMBEDDING_DIMENSION
from secval.hybrid_search.vector_storage import (
    CODE_VECTOR_COLLECTION,
    create_code_vector_collection,
    create_vector_point_id,
    delete_old_code_vectors,
    save_code_vectors,
)
from secval.shared_types import ChunkId, FileId, RepositoryId, SnapshotId


def create_code_chunk(chunk_id: str = "chunk-1") -> CodeChunk:
    """创建向量存储测试使用的代码块。"""

    return CodeChunk(
        chunk_id=ChunkId(chunk_id),
        file_id=FileId("file-1"),
        repository_id=RepositoryId("repository-1"),
        snapshot_id=SnapshotId("snapshot-1"),
        relative_path="src/UserService.java",
        language="java",
        chunk_type="method",
        content="void findUser() {}",
        start_line=1,
        end_line=1,
    )


def test_create_code_vector_collection() -> None:
    client = MagicMock()
    client.collection_exists.return_value = False

    created = create_code_vector_collection(client)

    assert created is True
    arguments = client.create_collection.call_args.kwargs
    assert arguments["collection_name"] == CODE_VECTOR_COLLECTION
    assert arguments["vectors_config"].size == EMBEDDING_DIMENSION
    assert arguments["vectors_config"].distance == models.Distance.COSINE
    assert client.create_payload_index.call_count == 6

    relative_path_call = client.create_payload_index.call_args_list[-1]
    relative_path_schema = relative_path_call.kwargs["field_schema"]
    assert relative_path_call.kwargs["field_name"] == "relative_path"
    assert relative_path_schema.prefix is True


def test_reject_existing_collection_with_wrong_dimension() -> None:
    client = MagicMock()
    client.collection_exists.return_value = True
    client.get_collection.return_value = SimpleNamespace(
        config=SimpleNamespace(
            params=SimpleNamespace(
                vectors=models.VectorParams(
                    size=10,
                    distance=models.Distance.COSINE,
                )
            )
        )
    )

    with pytest.raises(ValueError, match="向量维度不一致"):
        create_code_vector_collection(client)


def test_create_stable_qdrant_point_id() -> None:
    first_id = create_vector_point_id(ChunkId("chunk-1"))
    second_id = create_vector_point_id(ChunkId("chunk-1"))
    different_id = create_vector_point_id(ChunkId("chunk-2"))

    assert first_id == second_id
    assert first_id != different_id


def test_save_code_vectors() -> None:
    client = MagicMock()
    code_chunk = create_code_chunk()
    vector = [0.0] * EMBEDDING_DIMENSION

    saved_count = save_code_vectors(
        client=client,
        code_chunks=[code_chunk],
        vectors=[vector],
        index_run_id="run-1",
    )

    assert saved_count == 1
    arguments = client.upload_points.call_args.kwargs
    assert arguments["collection_name"] == CODE_VECTOR_COLLECTION
    assert arguments["batch_size"] == 64
    assert arguments["wait"] is True
    assert arguments["points"][0].payload["chunk_id"] == "chunk-1"
    assert arguments["points"][0].payload["index_run_id"] == "run-1"


def test_validate_all_vectors_before_writing() -> None:
    client = MagicMock()

    with pytest.raises(ValueError, match="Qdrant 向量维度错误"):
        save_code_vectors(
            client=client,
            code_chunks=[create_code_chunk()],
            vectors=[[0.0] * 10],
            index_run_id="run-1",
        )

    client.upload_points.assert_not_called()


def test_reject_duplicate_chunk_ids_before_vector_write() -> None:
    client = MagicMock()
    chunks = [create_code_chunk(), create_code_chunk()]
    vectors = [[0.0] * EMBEDDING_DIMENSION for _ in chunks]

    with pytest.raises(ValueError, match="代码块 ID 不能重复"):
        save_code_vectors(
            client=client,
            code_chunks=chunks,
            vectors=vectors,
            index_run_id="run-1",
        )

    client.upload_points.assert_not_called()


def test_delete_only_vectors_from_older_run() -> None:
    client = MagicMock()

    delete_old_code_vectors(
        client=client,
        repository_id=RepositoryId("repository-1"),
        snapshot_id=SnapshotId("snapshot-1"),
        current_index_run_id="run-2",
    )

    arguments = client.delete.call_args.kwargs
    point_filter = arguments["points_selector"]
    assert arguments["collection_name"] == CODE_VECTOR_COLLECTION
    assert point_filter.must[0].match.value == "repository-1"
    assert point_filter.must[1].match.value == "snapshot-1"
    assert point_filter.must_not[0].match.value == "run-2"
    assert arguments["wait"] is True
