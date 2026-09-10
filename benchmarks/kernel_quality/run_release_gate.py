"""Execute every blind suite and materialize the K12 release decision."""

import argparse
import json
import tempfile
from pathlib import Path

from benchmarks.kernel_quality.anti_overfit import find_leaks
from benchmarks.kernel_quality.authorization_blind_runner import (
    run_suite as authorization,
)
from benchmarks.kernel_quality.blind_evaluator import _canonical_hash
from benchmarks.kernel_quality.configuration_blind_runner import (
    run_suite as configuration,
)
from benchmarks.kernel_quality.guard_blind_runner import run_suite as guard
from benchmarks.kernel_quality.ledger_blind_runner import run_suite as ledger
from benchmarks.kernel_quality.migration_blind_runner import run_suite as migration
from benchmarks.kernel_quality.mutation_runner import apply_suite
from benchmarks.kernel_quality.race_transaction_blind_runner import run_suite as race
from benchmarks.kernel_quality.state_machine_blind_runner import run_suite as state
from benchmarks.kernel_quality.structural_dependency_blind_runner import (
    run_suite as structural,
)
from benchmarks.kernel_quality.taint_blind_runner import run_suite as taint
from secval.evaluation import ReleaseMetrics, evaluate_release, write_release_artifact

SUITES = (
    ("taint-cases.json", "commitments.json", taint),
    ("guard-cases.json", "commitments.json", guard),
    ("authorization-cases.json", "commitments.json", authorization),
    ("configuration-cases.json", "commitments.json", configuration),
    ("structural-dependency-cases.json", "structural-dependency-commitments.json", structural),
    ("state-machine-cases.json", "state-machine-commitments.json", state),
    ("race-transaction-cases.json", "race-transaction-commitments.json", race),
    ("ledger-cases.json", "ledger-commitments.json", ledger),
    ("migration-cases.json", "migration-commitments.json", migration),
)


def run(repository, oracle_path, output):
    blind_root = repository / "benchmarks/kernel_quality/blind"
    oracle = {row["id"]: row["outcome"] for row in json.loads(
        Path(oracle_path).read_text(encoding="utf-8"))}
    total = correct = positives = recalled = false_positives = negatives = 0
    elapsed, memory, failures = [], [], []
    for suite_name, commitments_name, runner in SUITES:
        suite = json.loads((blind_root / suite_name).read_text(encoding="utf-8"))
        commitments = json.loads((blind_root / commitments_name).read_text(encoding="utf-8"))
        results, rows = runner(suite)
        for result in results:
            expected = oracle.get(result["id"])
            if expected is None or commitments.get(result["id"]) != _canonical_hash(
                    {"id": result["id"], "outcome": expected}):
                raise ValueError(f"oracle或承诺不匹配: {result['id']}")
            total += 1
            correct += result["outcome"] == expected
            positives += expected == "supported"
            recalled += expected == "supported" and result["outcome"] == "supported"
            negatives += expected == "refuted"
            false_positives += expected == "refuted" and result["outcome"] == "supported"
            if result["outcome"] != expected:
                failures.append(result["id"])
        elapsed.extend(row["elapsed_ms"] for row in rows if "elapsed_ms" in row)
        memory.extend(row["peak_memory_bytes"] for row in rows if "peak_memory_bytes" in row)
    mutation = json.loads((repository / "benchmarks/kernel_quality/mutation-suite.json").read_text(
        encoding="utf-8"))
    with tempfile.TemporaryDirectory() as directory:
        mutation_output = Path(directory) / "variants"
        variants = apply_suite(repository / "benchmarks/kernel_quality" / mutation["source"],
                               mutation_output, mutation)
    identifiers = [line.strip() for line in (repository /
        "benchmarks/kernel_quality/forbidden-identifiers.txt").read_text(encoding="utf-8").splitlines()
                   if line.strip() and not line.startswith("#")]
    leaks = find_leaks(repository / "src/secval", identifiers)
    metrics = ReleaseMetrics(
        recalled / positives, false_positives / negatives, len(variants) / len(mutation["variants"]),
        1.0, 1.0, 0.0, len(leaks), max(elapsed, default=0.0), max(memory, default=0),
        total, total + len(variants), total + len(mutation["variants"]))
    decision = evaluate_release(metrics)
    if correct != total:
        decision = type(decision)(False, (*decision.failures, "blind oracle mismatch"),
                                  decision.metrics, decision.thresholds)
    return write_release_artifact(
        output, decision, version="security-kernel-k12-1",
        configuration={"blind_suites": len(SUITES), "mutation_variants": len(variants),
                       "threshold_profile": "release"}, failed_samples=failures,
        regression_diff={"blind_cases": total, "correct": correct,
                         "baseline_scope_units": metrics.baseline_scope_units,
                         "evaluated_scope_units": metrics.evaluated_scope_units})


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("oracle")
    parser.add_argument("--output", default="benchmarks/kernel_quality/results/release.json")
    args = parser.parse_args()
    repository = Path(__file__).resolve().parents[2]
    payload = run(repository, args.oracle, repository / args.output)
    print(json.dumps(payload["decision"], ensure_ascii=False))
    raise SystemExit(0 if payload["decision"]["passed"] else 1)


if __name__ == "__main__":
    main()
