import pytest

from secval.models.identifiers import ChunkId, RepositoryId
from secval.models.identifiers.resource_ids import require_resource_id


def test_resource_ids_keep_the_original_string_value() -> None:
    repository_id = RepositoryId("repository-123")
    chunk_id = ChunkId("chunk-456")

    assert repository_id == "repository-123"
    assert chunk_id == "chunk-456"


def test_require_resource_id_removes_outer_whitespace() -> None:
    assert require_resource_id("  repository-123  ", "repository_id") == (
        "repository-123"
    )


def test_require_resource_id_rejects_an_empty_value() -> None:
    with pytest.raises(ValueError, match="仓库 ID 不能为空"):
        require_resource_id("   ", "仓库 ID")
