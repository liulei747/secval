"""续跑必须维持仓库、快照、索引批次、范围和文件清单，不混用版本。"""

from copy import deepcopy

import pytest

from secval.services.audit_checkpoint import restore_checkpoint


def parent_task():
    return {"scope": {"repository_id": "repo", "snapshot_id": "snap", "source_snapshot_id": "source",
                      "index_run_id": "run", "scope_paths": ["src"], "approved_config_paths": []},
            "source_inventory": [{"path": "src/Test.java", "status": "captured", "digest": "digest"}],
            "checkpoint": {"version": 1, "phase": "investigation",
                           "messages": [{"role": "system", "content": "test"}], "state": {}}}


def test_matching_checkpoint_is_copied():
    parent = parent_task()
    result = restore_checkpoint(parent, parent["scope"], parent["source_inventory"])
    result["messages"][0]["content"] = "changed"
    assert parent["checkpoint"]["messages"][0]["content"] == "test"


@pytest.mark.parametrize("key", ["repository_id", "snapshot_id", "source_snapshot_id", "index_run_id",
                                 "scope_paths", "approved_config_paths"])
def test_changed_scope_rejects_resume(key):
    parent = parent_task()
    scope = deepcopy(parent["scope"])
    scope[key] = ["different"] if isinstance(scope[key], list) else "different"
    with pytest.raises(ValueError):
        restore_checkpoint(parent, scope, parent["source_inventory"])


@pytest.mark.parametrize("inventory", [None, [], [{"path": "src/Test.java", "digest": "changed"}]])
def test_changed_inventory_rejects_resume(inventory):
    parent = parent_task()
    with pytest.raises(ValueError):
        restore_checkpoint(parent, parent["scope"], inventory)
