import json

import pytest

from secval.evaluation import ReleaseMetrics, evaluate_release, write_release_artifact


def passing_metrics(**changes):
    values = {"blind_path_recall": 1.0, "safe_control_false_positive_rate": 0.0,
              "mutation_stability": 1.0, "finding_evidence_completeness": 1.0,
              "unknown_explainability": 1.0, "duplicate_root_rate": 0.0,
              "benchmark_identifier_leaks": 0, "maximum_elapsed_ms": 2.0,
              "maximum_peak_memory_bytes": 8192, "blind_cases": 30,
              "evaluated_scope_units": 100, "baseline_scope_units": 100}
    values.update(changes)
    return ReleaseMetrics(**values)


def test_release_requires_every_quality_and_resource_threshold():
    assert evaluate_release(passing_metrics()).passed
    fields = {
        "blind_path_recall": 0.84, "safe_control_false_positive_rate": 0.051,
        "mutation_stability": 0.94, "finding_evidence_completeness": 0.99,
        "unknown_explainability": 0.99, "duplicate_root_rate": 0.021,
        "benchmark_identifier_leaks": 1, "maximum_elapsed_ms": 101.0,
        "maximum_peak_memory_bytes": 1_048_577, "blind_cases": 23,
    }
    for name, value in fields.items():
        decision = evaluate_release(passing_metrics(**{name: value}))
        assert not decision.passed
        assert any(name.replace("blind_cases", "blind case count") in failure
                   for failure in decision.failures)


def test_scope_cannot_be_reduced_to_manufacture_performance_pass():
    decision = evaluate_release(passing_metrics(evaluated_scope_units=99))
    assert decision.failures == ("evaluated scope smaller than baseline",)


def test_release_artifact_records_reproducibility_and_failures(tmp_path):
    decision = evaluate_release(passing_metrics())
    path = tmp_path / "release.json"
    payload = write_release_artifact(path, decision, version="kernel-1",
                                     configuration={"suite": "blind-v1"},
                                     failed_samples=(), regression_diff={"new": 0})
    loaded = json.loads(path.read_text(encoding="utf-8"))
    assert loaded == payload
    assert loaded["hardware"]["platform"]
    assert loaded["decision"]["passed"] is True
    with pytest.raises(ValueError):
        write_release_artifact(path, decision, version="", configuration={})
