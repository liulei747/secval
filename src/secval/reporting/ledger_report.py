"""Deterministic JSON and Markdown views over the immutable ledger."""

import json
from dataclasses import asdict

from secval.adjudication import Verdict


def build_report(ledger, coverage):
    findings = []
    for candidate in ledger.candidates():
        event = ledger.current(candidate.id)
        if event.verdict in {Verdict.DUPLICATE, Verdict.REJECTED}:
            continue
        findings.append({
            "candidate_id": candidate.id, "kind": candidate.kind,
            "rule_id": candidate.rule_id, "verdict": event.verdict,
            "snapshot_id": candidate.snapshot_id, "entry_node_id": candidate.entry_node_id,
            "subject_node_id": candidate.subject_node_id,
            "resource_node_id": candidate.resource_node_id or candidate.root_cause_node_id,
            "path_node_ids": candidate.path_node_ids,
            "operation_node_id": candidate.operation_node_id,
            "controls": candidate.controls, "assumptions": candidate.assumptions,
            "unknowns": candidate.unknowns,
            "locations": tuple(asdict(location) for location in candidate.locations),
            "origins": candidate.evidence_origins,
            "history": tuple(asdict(row) for row in ledger.events()
                             if row.candidate_id == candidate.id),
        })
    findings.sort(key=lambda row: (row["rule_id"], row["candidate_id"]))
    return {"schema_version": 1, "findings": findings,
            "coverage": dict(sorted(coverage.items()))}


def to_json(report):
    return json.dumps(report, ensure_ascii=False, sort_keys=True, separators=(",", ":"),
                      default=str)


def to_markdown(report):
    lines = ["# Security analysis report", "", "## Findings", ""]
    for row in report["findings"]:
        lines.extend((f"### {row['rule_id']}", "", f"- Verdict: {row['verdict']}",
                      f"- Candidate: `{row['candidate_id']}`",
                      f"- Entry: `{row['entry_node_id']}`",
                      f"- Operation: `{row['operation_node_id']}`",
                      f"- Controls: {', '.join(row['controls']) or 'none'}",
                      f"- Unknowns: {', '.join(row['unknowns']) or 'none'}", ""))
    lines.extend(("## Coverage", "", "```json",
                  json.dumps(report["coverage"], ensure_ascii=False, sort_keys=True, indent=2),
                  "```", ""))
    return "\n".join(lines)
