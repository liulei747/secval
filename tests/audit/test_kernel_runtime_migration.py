from dataclasses import dataclass

import pytest

from secval.candidates import Candidate, CandidateKind, candidate_identity
from secval.facts import SourceLocation
from secval.services.kernel_runtime import (
    KernelCheckpointStore,
    KernelMigrationRuntime,
    LegacyReportView,
    publish_kernel_state,
)


def candidate(analyzer):
    rule = f"rule:{analyzer}"
    return Candidate(candidate_identity(rule, "snap", "entry", "operation", "root"),
                     CandidateKind.TAINT_FLOW, rule, analyzer, "1", "snap", "entry",
                     "operation", "root", ("entry", "operation"),
                     (SourceLocation("A.java", 1), SourceLocation("A.java", 2)),
                     "generic", (), (), (), (), ("graph",))


@dataclass
class Result:
    candidates: tuple
    metrics: dict


class Analyzer:
    def __init__(self, name, calls):
        self.name, self.calls = name, calls

    def analyze(self, snapshot):
        self.calls.append((self.name, snapshot))
        return Result((candidate(self.name),), {"runs": 1})


class FirstAnalyzer(Analyzer):
    pass


class SecondAnalyzer(Analyzer):
    pass


def test_budget_checkpoint_and_resume_are_per_analyzer_and_candidate(tmp_path):
    calls = []
    checkpoints = KernelCheckpointStore(tmp_path / "kernel-checkpoints.json")
    runtime = KernelMigrationRuntime((FirstAnalyzer("first", calls),
                                      SecondAnalyzer("second", calls)),
                                     checkpoint_store=checkpoints)
    first = runtime.run("task", "snap", "closure", budget=1,
                        legacy_hints=({"id": "legacy-1"},))
    assert first.status == "budget_exhausted"
    assert first.pending_analyzers == ("SecondAnalyzer",)
    assert first.metrics["legacy"] == {"bootstrap_hints": 1,
                                       "confirmation_capability": False}
    resumed = runtime.run("task", "snap", "closure", budget=1)
    assert resumed.status == "complete"
    assert calls == [("first", "snap"), ("second", "snap")]
    assert resumed.legacy_hint_ids == ("legacy-1",)
    assert checkpoints.load(f"task:candidate:{resumed.candidate_ids[-1]}")["status"] == "NEEDS_REVIEW"


def test_resume_rejects_changed_snapshot():
    runtime = KernelMigrationRuntime((FirstAnalyzer("first", []),))
    runtime.run("task", "snap", "closure", budget=0)
    with pytest.raises(ValueError, match="快照"):
        runtime.run("task", "other", "closure", budget=1)


def test_historical_report_is_copy_only_and_bridge_preserves_legacy_fields():
    original = {"findings": [{"title": "historical"}], "schemaVersion": 3}
    exported = LegacyReportView(original).export()
    exported["findings"].clear()
    assert original["findings"] == [{"title": "historical"}]

    class Store:
        def update(self, task_id, **changes):
            return {"id": task_id, "report": original, **changes}

    result = KernelMigrationRuntime(()).run("task", "snap", "closure", budget=0)
    task = publish_kernel_state(Store(), "task", result)
    assert task["report"] is original
    assert task["legacy_report_read_only"] is True


def test_old_heuristic_hints_cannot_enter_ledger_without_kernel_candidate():
    runtime = KernelMigrationRuntime(())
    result = runtime.run("task", "snap", "closure", budget=1,
                         legacy_hints=({"id": "legacy-only"},))
    assert result.legacy_hint_ids == ("legacy-only",)
    assert runtime.ledger.candidates() == ()


def test_result_exposes_verified_ledger_summary():
    runtime = KernelMigrationRuntime((FirstAnalyzer("first", []),))
    result = runtime.run("task", "snap", "closure", budget=1)
    assert result.ledger_candidate_count == 1
    assert result.ledger_event_count == 1
    assert result.ledger_chain_valid is True


def test_new_runtime_restores_ledger_and_does_not_rerun_completed_analyzers(tmp_path):
    calls = []
    checkpoints = KernelCheckpointStore(tmp_path / "kernel.json")
    first = KernelMigrationRuntime((FirstAnalyzer("first", calls),),
                                   checkpoint_store=checkpoints)
    original = first.run("task", "snap", "closure", budget=1)
    resumed = KernelMigrationRuntime((FirstAnalyzer("first", calls),),
                                     checkpoint_store=KernelCheckpointStore(tmp_path / "kernel.json"))
    restored = resumed.run("task", "snap", "closure", budget=1)
    assert calls == [("first", "snap")]
    assert restored.candidate_ids == original.candidate_ids
    assert restored.ledger_candidate_count == 1
    assert restored.ledger_event_count == 1
    assert restored.ledger_chain_valid is True
