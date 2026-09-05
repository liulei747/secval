"""关系图结果必须使用固定源码绑定的同一索引批次。"""

from unittest.mock import MagicMock

from secval.infrastructure.audit.index_evidence_tools import EvidenceTools


def test_graph_relation_uses_bound_run_and_filters_scope():
    connection = MagicMock()
    connection.transport.perform_request.return_value = {"pit_id": "fixed-view"}
    connection.search.return_value = {
        "timed_out": False, "_shards": {"failed": 0},
        "aggregations": {"runs": {"buckets": [{"key": "run-1"}]},
                         "missing_run": {"doc_count": 0}},
    }
    source_store = MagicMock()
    source_store.resolve_binding.return_value = "source-1"
    graph_store = MagicMock()
    graph_store.find_symbol.return_value = [
        {"name": "Order.run", "path": "src/Order.java"},
        {"name": "Other.run", "path": "outside/Other.java"},
    ]
    tools = EvidenceTools(connection, "repo", "snap", source_store, graph_store=graph_store)
    tools.call("restrict_scope", {"paths": ["src"]})

    result = tools.call("find_code_relations", {"symbol": "Order", "limit": 5})

    assert result["rows"] == [{"name": "Order.run", "path": "src/Order.java"}]
    graph_store.find_symbol.assert_called_once_with("repo", "snap", "run-1", "Order", 5)
    assert "必须read_file" in result["relation_note"]
