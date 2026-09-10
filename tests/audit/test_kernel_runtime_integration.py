from pathlib import Path

from secval.services.kernel_bootstrap import create_kernel_runner


class Store:
    def __init__(self):
        self.task = {
            "id": "task", "repository_id": "repo", "snapshot_id": "snap",
            "scope": {"source_snapshot_id": "source", "index_run_id": "run"},
            "scope_paths": [], "approved_config_paths": [],
            "path_sketches": [{"id": "legacy-1"}],
            "report": {"findings": [{"title": "legacy"}]},
        }

    def get(self, task_id):
        assert task_id == "task"
        return self.task.copy()

    def update(self, task_id, **changes):
        assert task_id == "task"
        self.task.update(changes)
        return self.task.copy()


def test_real_lifecycle_hook_persists_separate_kernel_state(tmp_path):
    store = Store()
    runner = create_kernel_runner(tmp_path / "audits.sqlite3")
    runner(store, "task")
    assert store.task["kernel_runtime"]["status"] == "complete"
    assert store.task["kernel_runtime"]["completed_analyzers"] == (
        "TaintEngine", "GuardEngine", "AuthorizationEngine", "ConfigurationEngine",
        "StructuralEngine", "DependencyReachabilityEngine", "StateMachineEngine",
        "RaceTransactionEngine",
    )
    assert store.task["kernel_runtime"]["legacy_hint_ids"] == ("legacy-1",)
    assert store.task["kernel_runtime"]["metrics"]["legacy"] == {
        "bootstrap_hints": 1, "confirmation_capability": False,
    }
    assert store.task["kernel_runtime"]["ledger_chain_valid"] is True
    assert store.task["kernel_runtime"]["ledger_report"]["coverage"] == {
        "analyzers_completed": 8, "analyzers_pending": 0, "snapshot_id": "snap",
    }
    assert store.task["legacy_report_read_only"] is True
    assert store.task["report"] == {"findings": [{"title": "legacy"}]}
    assert Path(tmp_path / "kernel-checkpoints.json").exists()
