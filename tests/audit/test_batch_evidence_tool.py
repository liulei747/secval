"""A single model action can gather several independently verified evidence items."""

from unittest.mock import MagicMock

import pytest

from secval.infrastructure.audit.index_evidence_tools import EvidenceTools
from secval.models.audit_contracts import CodeEvidence, ModelOutputError, ToolAction
from secval.models.audit_tools import iter_evidence_rows


def tools_with_files(contents):
    connection = MagicMock()
    connection.transport.perform_request.return_value = {"pit_id": "fixed-view"}
    connection.search.return_value = {
        "timed_out": False, "_shards": {"failed": 0},
        "aggregations": {"runs": {"buckets": [{"key": "run-1"}]},
                         "missing_run": {"doc_count": 0}},
    }
    source_store = MagicMock()
    source_store.resolve_binding.return_value = "source-1"
    source_store.read.side_effect = lambda source_id, path: contents[path]
    return EvidenceTools(connection, "repo", "snap", source_store)


def test_batch_reads_multiple_files_and_caps_returned_source():
    tools = tools_with_files({"a.py": "a" * 24000, "b.py": "b" * 24000,
                              "c.py": "c" * 24000, "d.py": "d" * 24000})
    operations = [{"tool": "read_file", "arguments": {"path": f"{name}.py"}}
                  for name in "abcd"]

    result = tools.call("batch_evidence", {"operations": operations})
    rows = list(iter_evidence_rows("batch_evidence", result))

    assert len(result["items"]) == 4
    assert result["content_characters"] == 36000
    assert sum(len(row["content"]) for row in rows) == 36000
    assert len(rows) == 3
    assert all(CodeEvidence.from_read(row) for row in rows)
    assert result["items"][-1]["result"]["rows"] == []


def test_batch_rejects_nesting_and_more_than_twelve_operations():
    read = {"tool": "read_file", "arguments": {"path": "a.py"}}
    with pytest.raises(ModelOutputError, match="不允许嵌套"):
        ToolAction.parse({"tool": "batch_evidence", "arguments": {"operations": [
            {"tool": "batch_evidence", "arguments": {"operations": [read]}}
        ]}})
    with pytest.raises(ModelOutputError, match="1到12"):
        ToolAction.parse({"tool": "batch_evidence", "arguments": {"operations": [read] * 13}})
