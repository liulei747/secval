from contextlib import contextmanager
from pathlib import Path

from secval.facts import NodeKind
from secval.services.kernel_bootstrap import _build_facts, create_kernel_runner


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


def test_production_fact_assembly_includes_dependency_manifests(tmp_path):
    (tmp_path / "Sample.java").write_text("class Sample { void run() {} }", encoding="utf-8")
    pom = """<project><dependencies><dependency><groupId>org.example</groupId>
    <artifactId>sample-lib</artifactId><version>1.2.3</version>
    </dependency></dependencies></project>"""
    (tmp_path / "pom.xml").write_text(pom, encoding="utf-8")

    class SourceStore:
        @contextmanager
        def indexing_directory(self, source_snapshot_id):
            assert source_snapshot_id == "source"
            yield tmp_path

        def iter_captured_files(self, source_snapshot_id):
            assert source_snapshot_id == "source"
            yield "pom.xml", None, pom

    task = {"repository_id": "repo", "snapshot_id": "snap",
            "scope": {"source_snapshot_id": "source"}, "approved_config_paths": []}
    facts = _build_facts(task, SourceStore(), None)
    dependencies = [row for row in facts.nodes("snap") if row.kind == NodeKind.DEPENDENCY]
    assert [(row.attributes["package"], row.attributes["version"])
            for row in dependencies] == [("org.example:sample-lib", "1.2.3")]
    assert "dependency_semantics" not in facts.coverage("snap")["gap_categories"]
