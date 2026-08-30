from unittest.mock import MagicMock, patch

from secval.hybrid_search.search_models import SearchQuery
from secval.hybrid_search.search_service import SearchService
from secval.shared_types import RepositoryId, SnapshotId


@patch("secval.hybrid_search.search_service.fuse_with_rrf")
@patch("secval.hybrid_search.search_service.search_by_vector")
@patch("secval.hybrid_search.search_service.search_by_keywords")
def test_run_complete_hybrid_search_flow(
    mock_keyword_search: MagicMock,
    mock_vector_search: MagicMock,
    mock_fuse: MagicMock,
) -> None:
    open_search_connection = MagicMock()
    qdrant_client = MagicMock()
    embedding_model = MagicMock()
    keyword_results = [MagicMock()]
    vector_results = [MagicMock()]
    final_results = [MagicMock()]
    mock_keyword_search.return_value = keyword_results
    mock_vector_search.return_value = vector_results
    mock_fuse.return_value = final_results
    service = SearchService(
        open_search_connection=open_search_connection,
        qdrant_client=qdrant_client,
        embedding_model=embedding_model,
    )
    query = SearchQuery(
        text="查找用户权限校验",
        repository_ids=[RepositoryId("repository-1")],
        snapshot_ids=[SnapshotId("snapshot-1")],
        top_k=10,
        language="java",
    )

    results = service.search(query)

    candidate_query = mock_keyword_search.call_args.kwargs["query"]
    assert candidate_query.top_k == 30
    assert candidate_query.text == query.text
    assert candidate_query.language == "java"
    mock_keyword_search.assert_called_once_with(
        connection=open_search_connection,
        query=candidate_query,
    )
    mock_vector_search.assert_called_once_with(
        qdrant_client=qdrant_client,
        open_search_connection=open_search_connection,
        embedding_model=embedding_model,
        query=candidate_query,
    )
    mock_fuse.assert_called_once_with(
        keyword_results=keyword_results,
        vector_results=vector_results,
        top_k=10,
    )
    assert results is final_results


@patch("secval.hybrid_search.search_service.fuse_with_rrf")
@patch("secval.hybrid_search.search_service.search_by_vector")
@patch("secval.hybrid_search.search_service.search_by_keywords")
def test_limit_internal_candidates_to_one_hundred(
    mock_keyword_search: MagicMock,
    mock_vector_search: MagicMock,
    mock_fuse: MagicMock,
) -> None:
    mock_keyword_search.return_value = []
    mock_vector_search.return_value = []
    mock_fuse.return_value = []
    service = SearchService(MagicMock(), MagicMock(), MagicMock())
    query = SearchQuery(
        text="find user",
        repository_ids=[RepositoryId("repository-1")],
        snapshot_ids=[SnapshotId("snapshot-1")],
        top_k=100,
    )

    service.search(query)

    candidate_query = mock_keyword_search.call_args.kwargs["query"]
    assert candidate_query.top_k == 100
