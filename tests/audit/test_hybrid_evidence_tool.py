"""混合搜索审计工具只返回通过固定视图校验的线索。"""

from unittest.mock import MagicMock

from secval.infrastructure.audit.index_evidence_tools import EvidenceTools
from secval.models.code import CodeChunk
from secval.models.identifiers import ChunkId, FileId, RepositoryId, SnapshotId
from secval.models.search import SearchResult


def candidate(chunk_id, path, rank):
    chunk = CodeChunk(ChunkId(chunk_id), FileId("file-" + chunk_id), RepositoryId("repo"),
                      SnapshotId("snap"), path, "java", "method", "void run() {}", 3, 3)
    return SearchResult(chunk, rank, 0.1, keyword_score=1.0 if rank == 1 else None,
                        vector_score=0.8, rrf_score=0.03)


def test_hybrid_search_filters_live_results_through_fixed_view():
    connection = MagicMock()
    connection.transport.perform_request.return_value = {"pit_id": "fixed-view"}
    connection.search.side_effect = [
        {"timed_out": False, "_shards": {"failed": 0}, "aggregations": {
            "runs": {"buckets": [{"key": "run-1"}]}, "missing_run": {"doc_count": 0}}},
        {"timed_out": False, "_shards": {"failed": 0}, "hits": {"hits": [
            {"_source": {"chunk_id": "inside", "relative_path": "src/Inside.java",
                         "index_run_id": "run-1", "start_line": 3, "end_line": 3}},
            {"_source": {"chunk_id": "wrong-run", "relative_path": "src/Old.java",
                         "index_run_id": "run-0", "start_line": 3, "end_line": 3}},
        ]}},
    ]
    source_store = MagicMock()
    source_store.resolve_binding.return_value = "source-1"
    source_store.inventory.return_value = []
    search = MagicMock()
    candidates = [candidate("inside", "src/Inside.java", 1),
                  candidate("wrong-run", "src/Old.java", 2),
                  candidate("not-in-pit", "src/New.java", 3)]
    search.keyword_retriever.search.return_value = candidates[:1]
    search.vector_retriever.search.return_value = candidates[1:]
    search.result_fusion.fuse.return_value = candidates

    tools = EvidenceTools(connection, "repo", "snap", source_store, search_service=search)
    tools.call("restrict_scope", {"paths": ["src"]})
    result = tools.call("hybrid_search", {"text": "订单归属检查", "top_k": 5})

    assert [row["chunk_id"] for row in result["rows"]] == ["inside"]
    assert "content" not in result["rows"][0]
    assert result["index_run_id"] == "run-1"
    assert "未调用外部重排序" in result["search_note"]
    search.reranker.rerank.assert_not_called()
    search.result_fusion.fuse.assert_called_once()


def test_hybrid_search_rejects_invalid_limit_before_search():
    tools = EvidenceTools(MagicMock(), "repo", "snap", MagicMock(), search_service=MagicMock())
    try:
        tools.call("hybrid_search", {"text": "x", "top_k": 21})
    except ValueError as error:
        assert "top_k" in str(error)
    else:
        raise AssertionError("超过上限的top_k必须被拒绝")
