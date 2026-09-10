"""Run opaque kernel-migration cases without loading their oracle."""

import argparse
import json
from pathlib import Path

from secval.candidates import Candidate, CandidateKind, candidate_identity
from secval.facts import SourceLocation
from secval.services.kernel_runtime import KernelMigrationRuntime


class BlindAnalyzer:
    def __init__(self, unknowns):
        self.unknowns = tuple(unknowns)

    def analyze(self, snapshot):
        rule = "blind:migration"
        row = Candidate(candidate_identity(rule, snapshot, "entry", "operation", "root"),
                        CandidateKind.TAINT_FLOW, rule, "blind-migration", "1", snapshot,
                        "entry", "operation", "root", ("entry", "operation"),
                        (SourceLocation("src/A.java", 1), SourceLocation("src/A.java", 2)),
                        "generic", (), (), (), self.unknowns, ("blind-facts",))
        return type("Result", (), {"candidates": (row,), "metrics": {"runs": 1}})()


def run_suite(suite):
    results, metrics = [], []
    for case in suite["cases"]:
        runtime = KernelMigrationRuntime((BlindAnalyzer(case["unknowns"]),))
        legacy = ({"id": "legacy-hint"},) if case["legacy"] else ()
        result = runtime.run(case["id"], case["id"], "closure", budget=case["budget"],
                             legacy_hints=legacy)
        if result.candidate_ids and not case["unknowns"]:
            outcome = "supported"
        elif result.legacy_hint_ids and not result.candidate_ids:
            outcome = "refuted"
        else:
            outcome = "inconclusive"
        results.append({"id": case["id"], "outcome": outcome})
        metrics.append({"budget_used": result.budget_used,
                        "legacy_can_confirm": result.metrics["legacy"]["confirmation_capability"]})
    return results, metrics


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("suite", nargs="?",
                        default="benchmarks/kernel_quality/blind/migration-cases.json")
    args = parser.parse_args()
    results, metrics = run_suite(json.loads(Path(args.suite).read_text(encoding="utf-8")))
    print(json.dumps({"results": results, "metrics": metrics}, ensure_ascii=False))


if __name__ == "__main__":
    main()
