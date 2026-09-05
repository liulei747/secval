"""框架入口识别只返回固定快照中的位置线索。"""

from unittest.mock import MagicMock

import pytest

from secval.infrastructure.audit.framework_entry_finder import find_framework_entries
from secval.models.audit_contracts import ModelOutputError, ToolAction


def create_store():
    store = MagicMock()
    store.inventory.side_effect = [[
        {"path": "src/Orders.java", "status": "captured"},
        {"path": "api.py", "status": "captured"},
        {"path": "notes.txt", "status": "captured"},
    ]]
    store.read.side_effect = lambda snapshot, path: {
        "src/Orders.java": "@RestController\nclass Orders {\n@GetMapping(\"/orders\")\nvoid list() {}\n}",
        "api.py": "@router.post('/orders')\ndef create_order():\n    pass\n",
    }[path]
    return store


def test_finds_java_and_python_entries_without_returning_source():
    rows = find_framework_entries(create_store(), "source-1", [], limit=10)

    assert [(row["framework"], row["marker"]) for row in rows] == [
        ("spring", "@RestController"),
        ("spring", "@GetMapping"),
        ("fastapi_flask", "@object.post"),
    ]
    assert all("content" not in row for row in rows)


def test_framework_filter_and_scope_are_applied():
    rows = find_framework_entries(create_store(), "source-1", ["src"], "spring", 10)
    assert len(rows) == 2
    assert all(row["path"] == "src/Orders.java" for row in rows)


def test_tool_contract_rejects_unknown_framework():
    with pytest.raises(ModelOutputError, match="framework"):
        ToolAction.parse({"tool": "find_entry_points",
                          "arguments": {"framework": "unknown"}})


def test_similar_annotation_names_are_not_reported_as_routes():
    store = MagicMock()
    store.inventory.return_value = [
        {"path": "Advice.java", "status": "captured"},
    ]
    store.read.return_value = "@ControllerAdvice\nclass Advice { @PathParam String id; }"

    assert find_framework_entries(store, "source-1", []) == []
