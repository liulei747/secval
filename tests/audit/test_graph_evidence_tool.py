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


def test_find_code_callers_uses_bound_run_and_filters_scope():
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
    graph_store.find_callers.return_value = [
        {"caller": "App.Controller.submit", "path": "src/Controller.java", "line": 3},
        {"caller": "App.Outside.submit", "path": "outside/Other.java", "line": 9},
    ]
    tools = EvidenceTools(connection, "repo", "snap", source_store, graph_store=graph_store)
    tools.call("restrict_scope", {"paths": ["src"]})

    result = tools.call("find_code_callers", {"symbol": "run", "limit": 5})

    assert result["rows"] == [{"caller": "App.Controller.submit", "path": "src/Controller.java", "line": 3}]
    graph_store.find_callers.assert_called_once_with("repo", "snap", "run-1", "run", 5)
    assert "Joern" in result["relation_note"]


def test_find_code_callees_filters_both_ends_to_the_allowed_scope():
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
    graph_store.find_callees.return_value = [
        {"caller": "App.submit", "callee": "App.run",
         "caller_path": "src/Controller.java", "path": "src/Service.java", "line": 8},
        {"caller": "App.submit", "callee": "Outside.run",
         "caller_path": "src/Controller.java", "path": "outside/Service.java", "line": 9},
    ]
    tools = EvidenceTools(connection, "repo", "snap", source_store, graph_store=graph_store)
    tools.call("restrict_scope", {"paths": ["src"]})

    result = tools.call("find_code_callees", {"symbol": "submit", "limit": 5})

    assert result["rows"] == [{"caller": "App.submit", "callee": "App.run",
                               "caller_path": "src/Controller.java",
                               "path": "src/Service.java", "line": 8}]
    graph_store.find_callees.assert_called_once_with("repo", "snap", "run-1", "submit", 5)


def test_find_code_type_relations_uses_bound_run_and_filters_scope():
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
    graph_store.find_type_relations.return_value = [
        {"symbol": "demo.Service", "relation": "EXTENDS", "parent": "demo.Base",
         "path": "src/Service.java", "line": 4, "overrides": []},
        {"symbol": "demo.Outside", "relation": "IMPLEMENTS", "parent": "demo.I",
         "path": "outside/I.java", "line": 9, "overrides": []},
    ]
    tools = EvidenceTools(connection, "repo", "snap", source_store, graph_store=graph_store)
    tools.call("restrict_scope", {"paths": ["src"]})

    result = tools.call("find_code_type_relations", {"symbol": "Service", "limit": 5})

    assert result["rows"] == [
        {"symbol": "demo.Service", "relation": "EXTENDS", "parent": "demo.Base",
         "path": "src/Service.java", "line": 4, "overrides": []}
    ]
    graph_store.find_type_relations.assert_called_once_with(
        "repo", "snap", "run-1", "Service", 5
    )


def test_dispatch_targets_pass_receiver_type_to_graph_store():
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
    graph_store.find_dispatch_targets.return_value = [
        {"base_method": "demo.Greeter.greet()",
         "candidate_kind": "dispatch_candidates",
         "implementations": ["demo.AService.greet()"]}
    ]
    tools = EvidenceTools(connection, "repo", "snap", source_store, graph_store=graph_store)

    result = tools.call("find_dispatch_targets", {
        "symbol": "greet", "limit": 5, "receiver_type": "Greeter"
    })

    assert result["rows"][0]["candidate_kind"] == "dispatch_candidates"
    graph_store.find_dispatch_targets.assert_called_once_with(
        "repo", "snap", "run-1", "greet", 5, receiver_type="Greeter"
    )
