import hashlib
import json
from pathlib import Path

import pytest

from benchmarks.audit_quality.cases import CASES, model_input
from benchmarks.kernel_quality.anti_overfit import find_leaks
from benchmarks.kernel_quality.authorization_blind_runner import (
    run_suite as run_authorization_blind_suite,
)
from benchmarks.kernel_quality.blind_evaluator import _canonical_hash, evaluate
from benchmarks.kernel_quality.configuration_blind_runner import (
    run_suite as run_configuration_blind_suite,
)
from benchmarks.kernel_quality.guard_blind_runner import (
    run_suite as run_guard_blind_suite,
)
from benchmarks.kernel_quality.ledger_blind_runner import (
    run_suite as run_ledger_blind_suite,
)
from benchmarks.kernel_quality.migration_blind_runner import (
    run_suite as run_migration_blind_suite,
)
from benchmarks.kernel_quality.mutation_runner import apply_manifest, apply_suite
from benchmarks.kernel_quality.race_transaction_blind_runner import (
    run_suite as run_race_transaction_blind_suite,
)
from benchmarks.kernel_quality.state_machine_blind_runner import (
    run_suite as run_state_machine_blind_suite,
)
from benchmarks.kernel_quality.structural_dependency_blind_runner import (
    run_suite as run_structural_dependency_blind_suite,
)
from benchmarks.kernel_quality.taint_blind_runner import (
    run_suite as run_taint_blind_suite,
)


def test_expected_oracle_is_not_exported_to_model_input():
    for case in CASES:
        exported = model_input(case)
        assert "expected" not in exported
        assert case["expected"]["reason"] not in repr(exported)


def test_mutation_runner_renames_wraps_replaces_and_moves(tmp_path):
    source = tmp_path / "source"
    source.mkdir()
    (source / "Service.java").write_text(
        "class Service { void load(String id) { legacy(id); } }", encoding="utf-8")
    output = tmp_path / "variant"
    apply_manifest(source, output, {"operations": [
        {"kind": "rename_identifier", "path": "Service.java", "from": "id", "to": "key"},
        {"kind": "replace_api", "path": "Service.java", "from": "legacy(key)", "to": "modern(key)"},
        {"kind": "wrap_text", "path": "Service.java", "text": "modern(key)",
         "before": "wrapper(() -> ", "after": ")"},
        {"kind": "move", "path": "Service.java", "to": "rearranged/Service.java"},
    ]})
    assert (output / "rearranged" / "Service.java").read_text(encoding="utf-8") == (
        "class Service { void load(String key) { wrapper(() -> modern(key)); } }")
    assert (source / "Service.java").exists()


def test_mutation_runner_rejects_in_place_and_traversal(tmp_path):
    source = tmp_path / "source"
    source.mkdir()
    (source / "A.java").write_text("class A {}", encoding="utf-8")
    with pytest.raises(ValueError):
        apply_manifest(source, source, {"operations": []})
    with pytest.raises(ValueError):
        apply_manifest(source, tmp_path / "out", {
            "operations": [{"kind": "move", "path": "../A.java", "to": "B.java"}]})


def test_runtime_contains_no_benchmark_specific_identifiers():
    repository = Path(__file__).resolve().parents[2]
    identifiers = [line.strip() for line in (
        repository / "benchmarks/kernel_quality/forbidden-identifiers.txt"
    ).read_text(encoding="utf-8").splitlines() if line.strip() and not line.startswith("#")]
    assert find_leaks(repository / "src/secval", identifiers) == []


def test_frozen_baseline_sources_have_not_changed():
    repository = Path(__file__).resolve().parents[2]
    baseline = json.loads((repository / "benchmarks/kernel_quality/baseline.json").read_text(
        encoding="utf-8"))
    for field in ("comparison", "prior_report"):
        path = repository / baseline["source"][field]
        assert hashlib.sha256(path.read_bytes()).hexdigest() == baseline["source"][field + "_sha256"]


def test_mutation_suite_builds_all_required_variant_classes(tmp_path):
    repository = Path(__file__).resolve().parents[2]
    suite = json.loads((repository / "benchmarks/kernel_quality/mutation-suite.json").read_text(
        encoding="utf-8"))
    source = repository / "benchmarks/kernel_quality" / suite["source"]
    variants = apply_suite(source, tmp_path / "variants", suite)
    assert {path.name for path in variants} == {
        "renamed", "wrapped", "api-replaced", "rearranged", "config-format"}
    assert (tmp_path / "variants/config-format/application.yml").exists()
    assert not (tmp_path / "variants/config-format/application.properties").exists()


def test_blind_evaluator_requires_external_committed_oracle(tmp_path):
    suite_root = tmp_path / "suite"
    suite_root.mkdir()
    oracle = [{"id": "opaque-1", "outcome": "refuted"}]
    commitments = {"opaque-1": _canonical_hash(oracle[0])}
    results = [{"id": "opaque-1", "outcome": "refuted"}]
    (suite_root / "commitments.json").write_text(json.dumps(commitments), encoding="utf-8")
    (suite_root / "results.json").write_text(json.dumps(results), encoding="utf-8")
    external = tmp_path / "private-oracle.json"
    external.write_text(json.dumps(oracle), encoding="utf-8")
    assert evaluate(suite_root / "results.json", external, suite_root / "commitments.json",
                    suite_root)["passed"]
    with pytest.raises(ValueError, match="oracle必须位于"):
        evaluate(suite_root / "results.json", suite_root / "oracle.json",
                 suite_root / "commitments.json", suite_root)


def test_taint_engine_blind_results_match_external_committed_oracle(tmp_path):
    repository = Path(__file__).resolve().parents[2]
    suite_root = repository / "benchmarks/kernel_quality/blind"
    suite = json.loads((suite_root / "taint-cases.json").read_text(encoding="utf-8"))
    results, metrics = run_taint_blind_suite(suite)
    results_path = tmp_path / "frozen-results.json"
    results_path.write_text(json.dumps(results), encoding="utf-8")
    external_oracle = tmp_path / "private-oracle.json"
    external_oracle.write_text(json.dumps([
        {"id": "blind-javaspring-01", "outcome": "supported"},
        {"id": "blind-javaspring-02", "outcome": "refuted"},
        {"id": "blind-javaspring-03", "outcome": "inconclusive"},
    ]), encoding="utf-8")
    score = evaluate(results_path, external_oracle, suite_root / "commitments.json", suite_root)
    assert score == {"cases": 3, "correct": 3, "accuracy": 1.0, "passed": True}
    assert all(row["elapsed_ms"] >= 0 and row["peak_memory_bytes"] > 0 for row in metrics)


def test_guard_engine_blind_results_match_external_committed_oracle(tmp_path):
    repository = Path(__file__).resolve().parents[2]
    suite_root = repository / "benchmarks/kernel_quality/blind"
    suite = json.loads((suite_root / "guard-cases.json").read_text(encoding="utf-8"))
    results, metrics = run_guard_blind_suite(suite)
    results_path = tmp_path / "guard-results.json"
    results_path.write_text(json.dumps(results), encoding="utf-8")
    external_oracle = tmp_path / "guard-oracle.json"
    external_oracle.write_text(json.dumps([
        {"id": "blind-javaspring-01", "outcome": "supported"},
        {"id": "blind-javaspring-02", "outcome": "refuted"},
        {"id": "blind-javaspring-03", "outcome": "inconclusive"},
    ]), encoding="utf-8")
    assert evaluate(results_path, external_oracle, suite_root / "commitments.json",
                    suite_root)["passed"]
    assert all(row["elapsed_ms"] >= 0 and row["peak_memory_bytes"] > 0 for row in metrics)


def test_authorization_blind_results_match_external_committed_oracle(tmp_path):
    repository = Path(__file__).resolve().parents[2]
    suite_root = repository / "benchmarks/kernel_quality/blind"
    suite = json.loads((suite_root / "authorization-cases.json").read_text(encoding="utf-8"))
    results, metrics = run_authorization_blind_suite(suite)
    results_path = tmp_path / "authorization-results.json"
    results_path.write_text(json.dumps(results), encoding="utf-8")
    external_oracle = tmp_path / "authorization-oracle.json"
    external_oracle.write_text(json.dumps([
        {"id": "blind-javaspring-01", "outcome": "supported"},
        {"id": "blind-javaspring-02", "outcome": "refuted"},
        {"id": "blind-javaspring-03", "outcome": "inconclusive"},
    ]), encoding="utf-8")
    assert evaluate(results_path, external_oracle, suite_root / "commitments.json",
                    suite_root)["passed"]
    assert all(row["elapsed_ms"] >= 0 and row["peak_memory_bytes"] > 0 for row in metrics)


def test_configuration_blind_results_match_external_committed_oracle(tmp_path):
    repository = Path(__file__).resolve().parents[2]
    suite_root = repository / "benchmarks/kernel_quality/blind"
    suite = json.loads((suite_root / "configuration-cases.json").read_text(encoding="utf-8"))
    results, metrics = run_configuration_blind_suite(suite)
    results_path = tmp_path / "configuration-results.json"
    results_path.write_text(json.dumps(results), encoding="utf-8")
    external_oracle = tmp_path / "configuration-oracle.json"
    external_oracle.write_text(json.dumps([
        {"id": "blind-javaspring-01", "outcome": "supported"},
        {"id": "blind-javaspring-02", "outcome": "refuted"},
        {"id": "blind-javaspring-03", "outcome": "inconclusive"},
    ]), encoding="utf-8")
    assert evaluate(results_path, external_oracle, suite_root / "commitments.json",
                    suite_root)["passed"]
    assert all(row["elapsed_ms"] >= 0 and row["peak_memory_bytes"] > 0 for row in metrics)


def test_structural_dependency_blind_results_match_external_committed_oracle(tmp_path):
    repository = Path(__file__).resolve().parents[2]
    suite_root = repository / "benchmarks/kernel_quality/blind"
    suite = json.loads((suite_root / "structural-dependency-cases.json").read_text(
        encoding="utf-8"))
    results, metrics = run_structural_dependency_blind_suite(suite)
    results_path = tmp_path / "k9-results.json"
    results_path.write_text(json.dumps(results), encoding="utf-8")
    oracle = tmp_path / "k9-oracle.json"
    oracle.write_text(json.dumps([
        {"id": "k9-blind-01", "outcome": "supported"},
        {"id": "k9-blind-02", "outcome": "refuted"},
        {"id": "k9-blind-03", "outcome": "inconclusive"},
        {"id": "k9-blind-04", "outcome": "supported"},
        {"id": "k9-blind-05", "outcome": "refuted"},
        {"id": "k9-blind-06", "outcome": "inconclusive"},
    ]), encoding="utf-8")
    score = evaluate(results_path, oracle,
                     suite_root / "structural-dependency-commitments.json", suite_root)
    assert score == {"cases": 6, "correct": 6, "accuracy": 1.0, "passed": True}
    assert all(row["elapsed_ms"] >= 0 and row["peak_memory_bytes"] > 0 for row in metrics)


def test_state_machine_blind_results_match_external_committed_oracle(tmp_path):
    repository = Path(__file__).resolve().parents[2]
    suite_root = repository / "benchmarks/kernel_quality/blind"
    suite = json.loads((suite_root / "state-machine-cases.json").read_text(encoding="utf-8"))
    results, metrics = run_state_machine_blind_suite(suite)
    results_path = tmp_path / "state-results.json"
    results_path.write_text(json.dumps(results), encoding="utf-8")
    oracle = tmp_path / "state-oracle.json"
    oracle.write_text(json.dumps([
        {"id": "state-blind-01", "outcome": "supported"},
        {"id": "state-blind-02", "outcome": "refuted"},
        {"id": "state-blind-03", "outcome": "inconclusive"},
    ]), encoding="utf-8")
    score = evaluate(results_path, oracle, suite_root / "state-machine-commitments.json",
                     suite_root)
    assert score == {"cases": 3, "correct": 3, "accuracy": 1.0, "passed": True}
    assert all(row["elapsed_ms"] >= 0 and row["peak_memory_bytes"] > 0 for row in metrics)


def test_race_transaction_blind_results_match_external_committed_oracle(tmp_path):
    repository = Path(__file__).resolve().parents[2]
    suite_root = repository / "benchmarks/kernel_quality/blind"
    suite = json.loads((suite_root / "race-transaction-cases.json").read_text(encoding="utf-8"))
    results, metrics = run_race_transaction_blind_suite(suite)
    results_path = tmp_path / "race-results.json"
    results_path.write_text(json.dumps(results), encoding="utf-8")
    oracle = tmp_path / "race-oracle.json"
    oracle.write_text(json.dumps([
        {"id": "race-blind-01", "outcome": "supported"},
        {"id": "race-blind-02", "outcome": "refuted"},
        {"id": "race-blind-03", "outcome": "inconclusive"},
    ]), encoding="utf-8")
    score = evaluate(results_path, oracle, suite_root / "race-transaction-commitments.json",
                     suite_root)
    assert score == {"cases": 3, "correct": 3, "accuracy": 1.0, "passed": True}
    assert all(row["elapsed_ms"] >= 0 and row["peak_memory_bytes"] > 0 for row in metrics)


def test_ledger_blind_results_match_external_committed_oracle(tmp_path):
    repository = Path(__file__).resolve().parents[2]
    suite_root = repository / "benchmarks/kernel_quality/blind"
    suite = json.loads((suite_root / "ledger-cases.json").read_text(encoding="utf-8"))
    results, metrics = run_ledger_blind_suite(suite)
    results_path = tmp_path / "ledger-results.json"
    results_path.write_text(json.dumps(results), encoding="utf-8")
    oracle = tmp_path / "ledger-oracle.json"
    oracle.write_text(json.dumps([
        {"id": "ledger-blind-01", "outcome": "supported"},
        {"id": "ledger-blind-02", "outcome": "refuted"},
        {"id": "ledger-blind-03", "outcome": "inconclusive"},
    ]), encoding="utf-8")
    score = evaluate(results_path, oracle, suite_root / "ledger-commitments.json", suite_root)
    assert score == {"cases": 3, "correct": 3, "accuracy": 1.0, "passed": True}
    assert all(row["chain_valid"] for row in metrics)


def test_migration_blind_results_match_external_committed_oracle(tmp_path):
    repository = Path(__file__).resolve().parents[2]
    suite_root = repository / "benchmarks/kernel_quality/blind"
    suite = json.loads((suite_root / "migration-cases.json").read_text(encoding="utf-8"))
    results, metrics = run_migration_blind_suite(suite)
    results_path = tmp_path / "migration-results.json"
    results_path.write_text(json.dumps(results), encoding="utf-8")
    oracle = tmp_path / "migration-oracle.json"
    oracle.write_text(json.dumps([
        {"id": "migration-blind-01", "outcome": "supported"},
        {"id": "migration-blind-02", "outcome": "refuted"},
        {"id": "migration-blind-03", "outcome": "inconclusive"},
    ]), encoding="utf-8")
    score = evaluate(results_path, oracle, suite_root / "migration-commitments.json", suite_root)
    assert score == {"cases": 3, "correct": 3, "accuracy": 1.0, "passed": True}
    assert all(not row["legacy_can_confirm"] for row in metrics)
