import json
from pathlib import Path

import pytest

from benchmarks.kernel_quality.run_release_gate import run

ORACLE = [
    {"id": "blind-javaspring-01", "outcome": "supported"},
    {"id": "blind-javaspring-02", "outcome": "refuted"},
    {"id": "blind-javaspring-03", "outcome": "inconclusive"},
    *({"id": f"k9-blind-{number:02d}", "outcome": outcome}
      for number, outcome in enumerate(("supported", "refuted", "inconclusive",
                                        "supported", "refuted", "inconclusive"), 1)),
    *({"id": f"state-blind-{number:02d}", "outcome": outcome}
      for number, outcome in enumerate(("supported", "refuted", "inconclusive"), 1)),
    *({"id": f"race-blind-{number:02d}", "outcome": outcome}
      for number, outcome in enumerate(("supported", "refuted", "inconclusive"), 1)),
    *({"id": f"ledger-blind-{number:02d}", "outcome": outcome}
      for number, outcome in enumerate(("supported", "refuted", "inconclusive"), 1)),
    *({"id": f"migration-blind-{number:02d}", "outcome": outcome}
      for number, outcome in enumerate(("supported", "refuted", "inconclusive"), 1)),
]


def test_aggregate_release_gate_runs_all_independent_suites(tmp_path):
    repository = Path(__file__).resolve().parents[2]
    oracle = tmp_path / "external-oracle.json"
    oracle.write_text(json.dumps(ORACLE), encoding="utf-8")
    payload = run(repository, oracle, tmp_path / "release.json")
    assert payload["decision"]["passed"] is True
    assert payload["decision"]["metrics"]["blind_cases"] == 30
    assert payload["decision"]["metrics"]["mutation_stability"] == 1.0


def test_release_runner_rejects_oracle_commitment_mismatch(tmp_path):
    repository = Path(__file__).resolve().parents[2]
    oracle = tmp_path / "external-oracle.json"
    changed = [dict(row) for row in ORACLE]
    changed[0]["outcome"] = "refuted"
    oracle.write_text(json.dumps(changed), encoding="utf-8")
    with pytest.raises(ValueError, match="承诺"):
        run(repository, oracle, tmp_path / "release.json")
