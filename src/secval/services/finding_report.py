"""仅提升当前详情版本与复核指纹一致的静态候选，保留未提升原因。"""

import hashlib
import json
from dataclasses import asdict

from secval.models.audit_contracts import CodeEvidence


def detail_digest(detail):
    return hashlib.sha256(json.dumps(detail, sort_keys=True, ensure_ascii=False,
                                     separators=(",", ":")).encode()).hexdigest()


def finding_identity(detail, evidence):
    root = evidence[detail["root_control"]]
    anchor = {"repository_id": root["repository_id"], "ruleId": detail["ruleId"],
              "path": root["relative_path"], "line": root["start_line"]}
    fingerprint = detail_digest(anchor)
    occurrence = detail_digest({**anchor, "snapshot_id": root["snapshot_id"],
                                "content_sha256": root["content_sha256"]})
    return {"findingId": "svf_" + fingerprint[:24], "occurrenceId": "svo_" + occurrence[:24],
            "fingerprints": {"algorithm": "secval/location-v1", "primary": fingerprint},
            "rootControlLocation": {"path": root["relative_path"], "startLine": root["start_line"],
                                    "endLine": root["end_line"]}}


def assemble_findings(details, investigations, validations, evidence):
    latest = {detail["investigation_id"]: detail for detail in details}
    reviews = {review["investigation_id"]: review for review in validations}
    findings, deferred = [], []
    for item in investigations:
        if item.get("status") != "supported":
            continue
        detail = latest.get(item["id"])
        review = reviews.get(item["id"])
        if detail is None or review is None or review.get("detail_sha256") != detail_digest(detail):
            deferred.append({"id": item["id"], "reason": "缺少当前详情版本的独立复核"})
            continue
        if review["outcome"] != "supported":
            continue
        refs = list(dict.fromkeys([*detail["rootCause"]["evidenceRefs"],
                                   *detail["attackPath"]["evidenceRefs"], *review["evidence_ids"]]))
        notes = {note["evidence_id"]: note for note in detail.get("evidenceNotes", [])}
        code_evidence = []
        for ref in refs:
            row = asdict(CodeEvidence.from_read(evidence[ref]))
            if ref in notes:
                row.update(role=notes[ref]["role"], explanation=notes[ref]["explanation"],
                           explanation_origin="model_candidate_reviewed")
            else:
                row["explanation_origin"] = "source_only"
            code_evidence.append(row)
        findings.append({**detail, **finding_identity(detail, evidence), "status": "static_supported_needs_review",
                         "provenance": {"source": "secval-self-built", "candidateId": item["id"]},
                         "detail_sha256": detail_digest(detail), "validation": review,
                         "codeEvidence": code_evidence})
    return findings, deferred
