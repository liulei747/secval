from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from qdrant_client.http import models

from secval.code_processing.code_models import CodeChunk
from secval.hybrid_search.search_models import SearchQuery
from secval.hybrid_search.vector_search import (
    build_vector_filter,
    search_by_vector,
)
from secval.hybrid_search.vector_storage import CODE_VECTOR_COLLECTION
from secval.shared_types import (
    ChunkId,
    FileId,
    RepositoryId,
    SnapshotId,
)


def create_query() -> SearchQuery:
    """创建包含全部过滤条件的测试查询。"""

    return SearchQuery(
        text="查找用户权限校验",
        repository_ids=[RepositoryId("repository-1")],
        snapshot_ids=[SnapshotId("snapshot-1")],
        top_k=5,
        language="java",
        path_prefix="src/service/",
        chunk_type="method",
    )


def create_chunk(chunk_id: str) -> CodeChunk:
    """创建向量搜索返回的完整代码块。"""

    return CodeChunk(
        chunk_id=ChunkId(chunk_id),
        file_id=FileId("file-1"),
        repository_id=RepositoryId("repository-1"),
        snapshot_id=SnapshotId("snapshot-1"),
        relative_path="src/service/UserService.java",
        language="java",
        chunk_type="method",
        content="void checkPermission() {}",
        start_line=1,
        end_line=1,
    )


def test_build_vector_filter() -> None:
    point_filter = build_vector_filter(create_query())

    conditions = {condition.key: condition for condition in point_filter.must}
    assert conditions["repository_id"].match.any == ["repository-1"]
    assert conditions["snapshot_id"].match.any == ["snapshot-1"]
    assert conditions["language"].match.value == "java"
    assert conditions["relative_path"].match.prefix == "src/service/"
    assert conditions["chunk_type"].match.value == "method"


@patch(
    "secval.hybrid_search.vector_search.search_by_vector."
    "load_code_chunks_by_ids"
)
def test_search_by_vector_returns_ranked_code_chunks(
    mock_load_chunks: MagicMock,
) -> None:
    qdrant_client = MagicMock()
    open_search_connection = MagicMock()
    embedding_model = MagicMock()
    embedding_model.embed_query.return_value = [0.1, 0.2]
    qdrant_client.query_points.return_value = SimpleNamespace(
        points=[
            SimpleNamespace(
                score=0.91,
                payload={"chunk_id": "chunk-2"},
            ),
            SimpleNamespace(
                score=0.82,
                payload={"chunk_id": "chunk-1"},
            ),
        ]
    )
    mock_load_chunks.return_value = [
        create_chunk("chunk-2"),
        create_chunk("chunk-1"),
    ]

    results = search_by_vector(
        qdrant_client=qdrant_client,
        open_search_connection=open_search_connection,
        embedding_model=embedding_model,
        query=create_query(),
    )

    arguments = qdrant_client.query_points.call_args.kwargs
    assert arguments["collection_name"] == CODE_VECTOR_COLLECTION
    assert arguments["query"] == [0.1, 0.2]
    assert arguments["limit"] == 5
    mock_load_chunks.assert_called_once_with(
        open_search_connection,
        [ChunkId("chunk-2"), ChunkId("chunk-1")],
    )
    assert [result.chunk.chunk_id for result in results] == [
        "chunk-2",
        "chunk-1",
    ]
    assert results[0].rank == 1
    assert results[0].vector_score == 0.91
    assert results[0].final_score == 0.91


def test_qdrant_prefix_filter_uses_match_prefix() -> None:
    point_filter = build_vector_filter(create_query())
    path_condition = next(
        condition
        for condition in point_filter.must
        if condition.key == "relative_path"
    )

    assert isinstance(path_condition.match, models.MatchPrefix)
