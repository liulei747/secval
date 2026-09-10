"""Bounded evidence needs and counterevidence decisions."""

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class EvidenceNeed:
    kind: str
    target_id: str
    reason: str


class NeedPlanner:
    MAPPINGS = (
        ("principal", "principal_source"), ("resource", "resource_ownership"),
        ("callee", "callee_implementation"), ("dependency", "dependency_summary"),
        ("profile", "effective_profile"), ("activation", "effective_profile"),
        ("isolation", "transaction_isolation"), ("constraint", "database_constraint"),
        ("sanitizer", "control_implementation"), ("control", "control_implementation"),
        ("entry", "caller_entry"),
    )

    def plan(self, candidate):
        needs = []
        for unknown in candidate.unknowns:
            kind = next((kind for token, kind in self.MAPPINGS if token in unknown.lower()),
                        "targeted_fact")
            target = (candidate.operation_node_id if kind in {"callee_implementation",
                      "transaction_isolation", "database_constraint", "control_implementation"}
                      else candidate.entry_node_id)
            row = EvidenceNeed(kind, target, unknown)
            if row not in needs:
                needs.append(row)
        return tuple(needs)


@dataclass(frozen=True, slots=True)
class CounterevidenceAssessment:
    evidence_ids: tuple[str, ...]
    all_paths_covered: bool
    reasons: tuple[str, ...]


class CounterevidenceRunner:
    ALLOWED = frozenset({"authentication_middleware", "sanitizer", "unreachable_proof",
                         "test_scope", "disabled_profile", "database_constraint",
                         "lock", "idempotency", "safe_branch"})

    def assess(self, rows):
        valid = [row for row in rows if row.get("kind") in self.ALLOWED
                 and row.get("evidence_id") and row.get("snapshot_id")
                 and row.get("covers_all_paths") is not None]
        return CounterevidenceAssessment(
            tuple(row["evidence_id"] for row in valid),
            bool(valid) and all(row["covers_all_paths"] for row in valid),
            tuple(str(row.get("reason", row["kind"])) for row in valid))
