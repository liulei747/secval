"""Score a SecVal report against the private SinkSpring expected-data file.

The expected file is read only after an audit has completed and is never sent to
the audited service or model.  Matching requires both a compatible finding type
and at least one benchmark-specific route/symbol/sink marker.
"""

import argparse
import json
import re
import urllib.request
from pathlib import Path


TYPE_ALIASES = {
    "deserialization": "unsafe_deserialization",
    "idor": "object_level_authorization",
    "privilege_escalation": "function_level_authorization",
    "spel_injection": "expression_injection",
    "ssti": "template_injection",
}


def load_json(location):
    if location.startswith(("http://", "https://")):
        with urllib.request.urlopen(location, timeout=30) as response:
            return json.load(response)
    return json.loads(Path(location).read_text(encoding="utf-8"))


def normalized(value):
    value = str(value or "").lower().replace("_", "-")
    return re.sub(r"\s+", " ", value)


def flatten(value):
    if isinstance(value, dict):
        return " ".join(flatten(item) for item in value.values())
    if isinstance(value, list):
        return " ".join(flatten(item) for item in value)
    return str(value or "")


def finding_type(finding):
    rule = str(finding.get("ruleId", "")).replace("-", "_")
    return TYPE_ALIASES.get(rule, rule)


def identity_text(finding):
    """Use report claims, not attached evidence that may mention safe neighbours."""
    attack_path = finding.get("attackPath", {})
    return flatten({
        "title": finding.get("title"),
        "summary": finding.get("summary"),
        "dataflow": attack_path.get("dataflow"),
        "reachability": attack_path.get("reachability"),
        "root": finding.get("rootControlLocation"),
    })


def expected_types(case):
    return {TYPE_ALIASES.get(value, value) for value in case.get("vulnerability_types", [])}


def matches(finding, case):
    if finding_type(finding) not in expected_types(case):
        return False
    text = normalized(identity_text(finding))
    return any(normalized(marker) in text for marker in case.get("match_any", []))


def score(expected, report):
    positives = [*expected.get("positives", []), *expected.get("config_findings", [])]
    controls = expected.get("safe_controls", [])
    findings = [row for row in report.get("findings", [])
                if row.get("status") == "static_supported_needs_review"]
    positive_hits = {case["id"]: [] for case in positives}
    control_hits = {case["id"]: [] for case in controls}
    matched_findings, duplicate_findings, unmatched_findings = set(), set(), set()
    claimed = set()
    for index, finding in enumerate(findings):
        hits = {case["id"] for case in positives if matches(finding, case)}
        safe_hits = {case["id"] for case in controls if matches(finding, case)}
        for case_id in hits:
            positive_hits[case_id].append(index)
        for case_id in safe_hits:
            control_hits[case_id].append(index)
        if safe_hits:
            matched_findings.add(index)
        elif not hits:
            unmatched_findings.add(index)
        elif hits <= claimed:
            duplicate_findings.add(index)
        else:
            matched_findings.add(index)
            claimed.update(hits)
    hit_ids = [case_id for case_id, rows in positive_hits.items() if rows]
    missed_ids = [case_id for case_id, rows in positive_hits.items() if not rows]
    false_control_ids = [case_id for case_id, rows in control_hits.items() if rows]
    tp, fn, fp, tn = len(hit_ids), len(missed_ids), len(false_control_ids), len(controls) - len(false_control_ids)
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / len(positives) if positives else 0.0
    return {
        "task_id": report.get("taskId"),
        "formal_findings": len(findings),
        "tp": tp, "fp_safe_controls": fp, "fn": fn, "tn": tn,
        "precision": precision, "recall": recall,
        "code_recall": sum(bool(positive_hits[row["id"]]) for row in expected.get("positives", []))
                       / max(1, len(expected.get("positives", []))),
        "config_recall": sum(bool(positive_hits[row["id"]]) for row in expected.get("config_findings", []))
                         / max(1, len(expected.get("config_findings", []))),
        "hit_ids": hit_ids, "missed_ids": missed_ids,
        "false_control_ids": false_control_ids,
        "duplicate_finding_count": len(duplicate_findings),
        "duplicate_finding_indexes": sorted(duplicate_findings),
        "unmatched_finding_count": len(unmatched_findings),
        "unmatched_finding_indexes": sorted(unmatched_findings),
        "positive_matches": {key: value for key, value in positive_hits.items() if value},
        "control_matches": {key: value for key, value in control_hits.items() if value},
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("expected")
    parser.add_argument("reports", nargs="+")
    args = parser.parse_args()
    expected = load_json(args.expected)
    print(json.dumps([score(expected, load_json(report)) for report in args.reports],
                     ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
