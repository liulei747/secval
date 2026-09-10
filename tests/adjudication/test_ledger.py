from dataclasses import replace

import pytest

from secval.adjudication import (
    CandidateLedger,
    CounterevidenceRunner,
    NeedPlanner,
    Verdict,
)
from secval.candidates import Candidate, CandidateKind, candidate_identity
from secval.facts import SourceLocation
from secval.reporting import build_report, to_json, to_markdown


def candidate(**changes):
    values = {"kind": CandidateKind.TAINT_FLOW, "rule_id": "flow:sql",
              "analyzer": "taint", "analyzer_version": "1", "snapshot_id": "snap",
              "entry_node_id": "entry", "operation_node_id": "sink",
              "root_cause_node_id": "root", "path_node_ids": ("entry", "sink"),
              "locations": (SourceLocation("A.java", 1), SourceLocation("A.java", 2)),
              "taint_kind": "sql", "flow_states": (), "controls": (),
              "assumptions": (), "unknowns": (), "evidence_origins": ("joern",),
              "resource_node_id": "resource"}
    values.update(changes)
    values["id"] = candidate_identity(values["rule_id"], values["snapshot_id"],
                                      values["entry_node_id"], values["operation_node_id"],
                                      values["root_cause_node_id"], values["resource_node_id"])
    return Candidate(**values)


def test_structured_identity_includes_resource_and_deduplicates_path_variants():
    first = candidate()
    second = replace(first, path_node_ids=("entry", "middle", "sink"),
                     locations=(SourceLocation("A.java", 1), SourceLocation("B.java", 3),
                                SourceLocation("A.java", 2)))
    other = candidate(resource_node_id="other")
    ledger = CandidateLedger()
    ledger.ingest(first, "closure-1")
    ledger.ingest(second, "closure-1")
    ledger.ingest(other, "closure-1")
    assert len(ledger.candidates()) == 2
    assert len(ledger.variants(first.id)) == 2


def test_six_verdicts_are_evidence_gated_and_events_are_append_only():
    ledger = CandidateLedger()
    row = candidate()
    duplicate = candidate(rule_id="flow:duplicate")
    ledger.ingest(row, "closure-1")
    ledger.ingest(duplicate, "closure-1")
    with pytest.raises(ValueError, match="未找到入口"):
        ledger.append(row.id, Verdict.UNREACHABLE, "no entry", ("search",), ("graph@1",),
                      "closure-1")
    with pytest.raises(ValueError, match="覆盖全部路径"):
        ledger.append(row.id, Verdict.DEFENDED, "guard", ("guard",), ("guard@1",),
                      "closure-1")
    ledger.append(row.id, Verdict.CONFIRMED, "complete graph", ("path",), ("taint@1",),
                  "closure-1")
    ledger.append(row.id, Verdict.DEFENDED, "global guard", ("guard",), ("guard@1",),
                  "closure-1", all_paths_covered=True)
    ledger.append(duplicate.id, Verdict.DUPLICATE, "same root", ("merge",), ("ledger@1",),
                  "closure-1", duplicate_of=row.id)
    assert ledger.current(row.id).verdict == Verdict.DEFENDED
    assert ledger.verify_chain()


def test_unknown_candidate_cannot_be_confirmed_and_closure_change_invalidates():
    ledger = CandidateLedger()
    row = candidate(unknowns=("runtime isolation level unknown",))
    ledger.ingest(row, "old")
    with pytest.raises(ValueError, match="未知项"):
        ledger.append(row.id, Verdict.CONFIRMED, "looks risky", ("x",), ("model@1",), "old")
    event = ledger.invalidate_changed_closure(row.id, "new", ("facts@2",))
    assert event.verdict == Verdict.NEEDS_REVIEW
    assert ledger.invalidate_changed_closure(row.id, "new", ("facts@2",)) is None


def test_need_planner_targets_known_nodes_and_counterevidence_requires_snapshot():
    row = candidate(unknowns=("callee implementation missing",
                              "runtime isolation level unknown"))
    needs = NeedPlanner().plan(row)
    assert {(need.kind, need.target_id) for need in needs} == {
        ("callee_implementation", "sink"), ("transaction_isolation", "sink")}
    assessment = CounterevidenceRunner().assess([
        {"kind": "lock", "evidence_id": "lock-1", "snapshot_id": "snap",
         "covers_all_paths": True},
        {"kind": "guess", "evidence_id": "bad", "snapshot_id": "snap",
         "covers_all_paths": True},
    ])
    assert assessment.evidence_ids == ("lock-1",)
    assert assessment.all_paths_covered


def test_report_is_deterministic_and_only_ledger_controls_verdict():
    ledger = CandidateLedger()
    row = candidate()
    ledger.ingest(row, "closure")
    ledger.append(row.id, Verdict.CONFIRMED, "verified", ("path",), ("engine@1",), "closure")
    report = build_report(ledger, {"parse_gaps": 0, "analyzers": 8})
    assert to_json(report) == to_json(build_report(ledger, {"analyzers": 8, "parse_gaps": 0}))
    assert "CONFIRMED" in to_markdown(report)
    assert report["findings"][0]["history"][-1]["reason"] == "verified"
