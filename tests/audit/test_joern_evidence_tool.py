"""Joern线索要映射回固定快照中的唯一相对路径。"""

from unittest.mock import MagicMock

from secval.infrastructure.audit.index_evidence_tools import EvidenceTools


def test_joern_call_location_uses_bound_run_and_snapshot_path():
    connection = MagicMock()
    connection.transport.perform_request.return_value = {"pit_id": "fixed-view"}
    connection.search.return_value = {
        "timed_out": False, "_shards": {"failed": 0},
        "aggregations": {"runs": {"buckets": [{"key": "run-1"}]},
                         "missing_run": {"doc_count": 0}},
    }
    source_store = MagicMock()
    source_store.resolve_binding.return_value = "source-1"
    source_store.inventory.return_value = [
        {"path": "src/Order.java", "status": "captured", "digest": "x"}
    ]
    joern = MagicMock()
    joern.find_calls.return_value = [
        {"method": "fetch", "path": "/joern-inputs/temp/src/Order.java", "line": 12},
        {"method": "fetch", "path": "/other/Outside.java", "line": 2},
    ]
    tools = EvidenceTools(connection, "repo", "snap", source_store, joern_client=joern)
    tools.call("restrict_scope", {"paths": ["src"]})

    result = tools.call("find_code_calls", {"method": "fetch", "limit": 5})

    assert result["rows"] == [{"method": "fetch", "path": "src/Order.java", "line": 12}]
    joern.find_calls.assert_called_once_with("run-1", "fetch", 5)
    assert "必须read_file" in result["path_note"]


def test_joern_data_path_is_dropped_when_any_step_is_outside_scope():
    connection = MagicMock()
    connection.transport.perform_request.return_value = {"pit_id": "fixed-view"}
    connection.search.return_value = {
        "timed_out": False, "_shards": {"failed": 0},
        "aggregations": {"runs": {"buckets": [{"key": "run-1"}]},
                         "missing_run": {"doc_count": 0}},
    }
    source_store = MagicMock()
    source_store.resolve_binding.return_value = "source-1"
    source_store.inventory.return_value = [
        {"path": "src/Order.java", "status": "captured", "digest": "x"},
        {"path": "outside/Other.java", "status": "captured", "digest": "y"},
    ]
    joern = MagicMock()
    joern.find_data_paths.return_value = [
        {"steps": [{"node_type": "PARAM", "path": "src/Order.java", "line": 3}]},
        {"steps": [{"node_type": "PARAM", "path": "src/Order.java", "line": 3},
                   {"node_type": "CALL", "path": "outside/Other.java", "line": 8}]},
    ]
    tools = EvidenceTools(connection, "repo", "snap", source_store, joern_client=joern)
    tools.call("restrict_scope", {"paths": ["src"]})

    result = tools.call("find_data_paths", {
        "source_method": "fetch", "sink_method": "execute", "limit": 4,
    })

    assert result["paths"] == [{"steps": [
        {"node_type": "PARAM", "path": "src/Order.java", "line": 3}
    ]}]
