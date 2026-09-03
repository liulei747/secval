from unittest.mock import MagicMock

from secval.infrastructure.reranker import NoopReranker
from secval.interfaces import RerankerError
from secval.models.search import SearchQuery
from secval.services.search_service import SearchService
from secval.shared_types import RepositoryId, SnapshotId


def test_run_complete_hybrid_search_flow() -> None:
    keyword_retriever = MagicMock()
    vector_retriever = MagicMock()
    result_fusion = MagicMock()
    reranker = MagicMock()
    reranker.candidate_count = 10
    keyword_results = [MagicMock()]
    vector_results = [MagicMock()]
    final_results = [MagicMock()]
    keyword_retriever.search.return_value = keyword_results
    vector_retriever.search.return_value = vector_results
    result_fusion.fuse.return_value = final_results
    reranker.rerank.return_value = final_results
    service = SearchService(
        keyword_retriever=keyword_retriever,
        vector_retriever=vector_retriever,
        result_fusion=result_fusion,
        reranker=reranker,
    )
    query = SearchQuery(
        text="查找用户权限校验",
        repository_ids=[RepositoryId("repository-1")],
        snapshot_ids=[SnapshotId("snapshot-1")],
        top_k=10,
        language="java",
    )

    results = service.search(query)

    candidate_query = keyword_retriever.search.call_args.args[0]
    assert candidate_query.top_k == 30
    assert candidate_query.text == query.text
    assert candidate_query.language == "java"
    keyword_retriever.search.assert_called_once_with(candidate_query)
    vector_retriever.search.assert_called_once_with(candidate_query)
    result_fusion.fuse.assert_called_once_with(
        keyword_results=keyword_results,
        vector_results=vector_results,
        top_k=10,
    )
    reranker.rerank.assert_called_once_with(
        query=query.text,
        candidates=final_results,
        top_k=10,
    )
    assert results is final_results


def test_limit_internal_candidates_to_one_hundred() -> None:
    keyword_retriever = MagicMock()
    vector_retriever = MagicMock()
    result_fusion = MagicMock()
    keyword_retriever.search.return_value = []
    vector_retriever.search.return_value = []
    result_fusion.fuse.return_value = []
    service = SearchService(
        keyword_retriever,
        vector_retriever,
        result_fusion,
        NoopReranker(),
    )
    query = SearchQuery(
        text="find user",
        repository_ids=[RepositoryId("repository-1")],
        snapshot_ids=[SnapshotId("snapshot-1")],
        top_k=100,
    )

    service.search(query)

    candidate_query = keyword_retriever.search.call_args.args[0]
    assert candidate_query.top_k == 100


def test_fall_back_to_rrf_when_reranker_fails() -> None:
    keyword_retriever = MagicMock()
    vector_retriever = MagicMock()
    result_fusion = MagicMock()
    reranker = MagicMock()
    reranker.candidate_count = 10
    reranker.rerank.side_effect = RerankerError("model unavailable")
    fused_results = [MagicMock(), MagicMock()]
    keyword_retriever.search.return_value = []
    vector_retriever.search.return_value = []
    result_fusion.fuse.return_value = fused_results
    service = SearchService(
        keyword_retriever,
        vector_retriever,
        result_fusion,
        reranker,
    )
    query = SearchQuery(
        text="find user",
        repository_ids=[RepositoryId("repository-1")],
        snapshot_ids=[SnapshotId("snapshot-1")],
        top_k=1,
    )

    assert service.search(query) == fused_results[:1]
