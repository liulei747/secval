"""[SECVAL-LEGACY-DISABLED]
本模块已从生产审计路径摘除（方案4-B）。审计报告不再依赖其输出；
代码与测试全部保留以便日后恢复，恢复方式见 docs/leg-b-status.md。
"""

"""Incremental dual-run bridge from the legacy audit to the analysis kernel."""

import json
from copy import deepcopy
from dataclasses import asdict, dataclass
from pathlib import Path

from secval.adjudication import CandidateLedger
from secval.reporting import build_report


@dataclass(frozen=True, slots=True)
class KernelRunResult:
    task_id: str
    snapshot_id: str
    status: str
    completed_analyzers: tuple[str, ...]
    pending_analyzers: tuple[str, ...]
    candidate_ids: tuple[str, ...]
    legacy_hint_ids: tuple[str, ...]
    metrics: dict
    budget_used: int
    ledger_candidate_count: int
    ledger_event_count: int
    ledger_chain_valid: bool
    ledger_report: dict


class KernelCheckpointStore:
    def __init__(self, path=None):
        self.path = Path(path) if path else None
        self.data = self._read()

    def _read(self):
        if self.path is None or not self.path.exists():
            return {}
        return json.loads(self.path.read_text(encoding="utf-8"))

    def save(self, task_id, state):
        self.data[task_id] = deepcopy(state)
        if self.path:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            temporary = self.path.with_suffix(self.path.suffix + ".tmp")
            temporary.write_text(json.dumps(self.data, ensure_ascii=False, sort_keys=True),
                                 encoding="utf-8")
            temporary.replace(self.path)

    def load(self, task_id):
        return deepcopy(self.data.get(task_id, {}))


class LegacyReportView:
    """Copy-only adapter preserving historical report fields during migration."""

    def __init__(self, report):
        self._report = deepcopy(report)

    def export(self):
        return deepcopy(self._report)


class KernelMigrationRuntime:
    def __init__(self, analyzers, *, checkpoint_store=None, ledger=None):
        self.analyzers = tuple(analyzers)
        self.checkpoints = checkpoint_store or KernelCheckpointStore()
        self.ledger = ledger or CandidateLedger()

    def run(self, task_id, snapshot_id, closure_hash, *, budget,
            legacy_hints=(), tool_versions=("kernel-runtime@1",)):
        if budget < 0:
            raise ValueError("kernel budget不能为负数")
        state = self.checkpoints.load(task_id)
        if state and state.get("snapshot_id") != snapshot_id:
            raise ValueError("续跑快照与检查点不一致")
        analyzer_plan = [self._analyzer_name(row) for row in self.analyzers]
        runtime_signature = json.dumps({"analyzers": analyzer_plan,
                                        "tool_versions": list(tool_versions)}, sort_keys=True)
        if state.get("runtime_signature") != runtime_signature:
            state = {"snapshot_id": snapshot_id}
        elif state.get("ledger_snapshot"):
            self.ledger = CandidateLedger.restore(state["ledger_snapshot"])
        completed = list(state.get("completed_analyzers", []))
        candidate_ids = list(state.get("candidate_ids", []))
        metrics = dict(state.get("metrics", {}))
        used = 0
        for analyzer in self.analyzers:
            name = self._analyzer_name(analyzer)
            if name in completed:
                continue
            if used >= budget:
                break
            result = analyzer.analyze(snapshot_id)
            for candidate in result.candidates:
                self.ledger.ingest(candidate, closure_hash)
                if candidate.id not in candidate_ids:
                    candidate_ids.append(candidate.id)
                self.checkpoints.save(f"{task_id}:candidate:{candidate.id}", {
                    "candidate_id": candidate.id, "analyzer": name, "status": "NEEDS_REVIEW"})
            completed.append(name)
            metrics[name] = deepcopy(result.metrics)
            used += 1
            self.checkpoints.save(task_id, {"snapshot_id": snapshot_id,
                                            "runtime_signature": runtime_signature,
                                            "completed_analyzers": completed,
                                            "candidate_ids": candidate_ids,
                                            "metrics": metrics,
                                            "ledger_snapshot": self.ledger.snapshot()})
        pending = [self._analyzer_name(analyzer) for analyzer in self.analyzers
                   if self._analyzer_name(analyzer) not in completed]
        hints = tuple(dict.fromkeys((*state.get("legacy_hint_ids", ()),
                                    *(str(row["id"]) for row in legacy_hints if row.get("id")))))
        fact_reader = next((getattr(row, "facts", None) or
                            getattr(getattr(row, "engine", None), "facts", None)
                            for row in self.analyzers
                            if (getattr(row, "facts", None) or
                                getattr(getattr(row, "engine", None), "facts", None)) is not None), None)
        fact_metrics = fact_reader.coverage(snapshot_id) if hasattr(fact_reader, "coverage") else {}
        result = KernelRunResult(task_id, snapshot_id, "complete" if not pending else "budget_exhausted",
                                 tuple(completed), tuple(pending), tuple(candidate_ids), hints,
                                 {"kernel": metrics, "facts": fact_metrics,
                                  "legacy": {"bootstrap_hints": len(hints),
                                             "confirmation_capability": False}}, used,
                                 len(self.ledger.candidates()), len(self.ledger.events()),
                                 self.ledger.verify_chain(),
                                 build_report(self.ledger, {"snapshot_id": snapshot_id,
                                                           "analyzers_completed": len(completed),
                                                           "analyzers_pending": len(pending)}))
        self.checkpoints.save(task_id, {"snapshot_id": snapshot_id,
                                        **self.checkpoints.load(task_id),
                                        "runtime_signature": runtime_signature,
                                        "status": result.status,
                                        "legacy_hint_ids": list(hints),
                                        "ledger_snapshot": self.ledger.snapshot()})
        return result

    @staticmethod
    def _analyzer_name(analyzer):
        return getattr(analyzer, "runtime_name", analyzer.__class__.__name__)


def publish_kernel_state(store, task_id, result):
    """Persist the migration view in the existing audit task without rewriting legacy output."""
    return store.update(task_id, kernel_runtime=asdict(result), legacy_report_read_only=True)


def publish_kernel_failure(store, task_id, error):
    """Expose a migration failure without changing the legacy task/report outcome."""
    return store.update(task_id, kernel_runtime={
        "status": "failed", "error": str(error), "legacy_confirmation_capability": False,
    }, legacy_report_read_only=True)
