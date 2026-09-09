"""仅提升当前详情版本与复核指纹一致的静态候选，保留未提升原因。"""

import hashlib
import json
import re
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


def _routes(finding):
    text = " ".join((finding.get("title", ""),
                     finding.get("attackPath", {}).get("reachability", {}).get("entrypoint", "")))
    routes = set(finding.get("mergedRoutes", [])) | set(re.findall(
        r"(?:GET|POST|PUT|PATCH|DELETE)\s+/[A-Za-z0-9_{}?=<>/.-]+", text, re.IGNORECASE))
    # Query examples and model-added placeholders describe the same endpoint;
    # they are not separate vulnerability occurrences.
    return {route.split("?", 1)[0].strip().upper() for route in routes}


def _sink_key(finding):
    text = " ".join((finding.get("title", ""),
                     finding.get("attackPath", {}).get("dataflow", {}).get("sink", ""))).lower()
    anchors = ("${", "order by", "executequery", "runtime.exec", "getruntime().exec", "processbuilder", "files.readstring",
               "files.writestring", "httpclient.send", "getresponsecode", "objectinputstream",
               "httpurlconnection", "openconnection", "xmldecoder", "decoder.readobject",
               "documentbuilder", "parseexpression", "template.process",
               "initialcontext", "jwt.decode", "location", "text_html", "text/html", "html",
               "changerole", "repository.find", "repository.update", "ownership",
               "management.endpoints.web.exposure",
               "h2.console", "include-stacktrace", "password", "client-secret")
    return next((anchor.lower() for anchor in anchors if anchor.lower() in text), "")


def _same_finding(left, right):
    if left.get("ruleId") != right.get("ruleId"):
        return False
    left_routes, right_routes = _routes(left), _routes(right)
    if left_routes and right_routes:
        # A formal finding is one rule at one HTTP entry. Discovery and
        # deterministic paths often name different hops of the same chain as
        # the sink, so requiring identical prose-level sink keys preserves
        # duplicates instead of distinguishing vulnerabilities.
        return bool(left_routes & right_routes)
    # Configuration and non-HTTP findings use the concrete key/sink plus file.
    return (_sink_key(left) and _sink_key(left) == _sink_key(right)
            and left.get("rootControlLocation", {}).get("path")
            == right.get("rootControlLocation", {}).get("path"))


def _deduplicate_findings(findings):
    merged = []
    for finding in findings:
        target = next((row for row in merged if _same_finding(row, finding)), None)
        if target is None:
            candidate = finding["provenance"].pop("candidateId", None)
            finding["provenance"]["candidateIds"] = list(dict.fromkeys([
                *finding["provenance"].get("candidateIds", []), candidate,
            ]))
            finding["provenance"]["candidateIds"] = [row for row in finding["provenance"]["candidateIds"] if row]
            merged.append(finding)
            continue
        target["provenance"]["candidateIds"] = list(dict.fromkeys([
            *target["provenance"].get("candidateIds", []),
            *finding["provenance"].get("candidateIds", []),
            finding["provenance"].get("candidateId"),
        ]))
        target["provenance"]["candidateIds"] = [row for row in target["provenance"]["candidateIds"] if row]
        # CodeEvidence is exported with the public ``id`` field.  Accept the
        # historical internal name as well so persisted reports remain
        # mergeable across schema versions.
        evidence_id = lambda row: row.get("id") or row.get("evidence_id")
        known = {evidence_id(row) for row in target["codeEvidence"]}
        target["codeEvidence"].extend(row for row in finding["codeEvidence"]
                                      if evidence_id(row) not in known)
        target["mergedRoutes"] = sorted(_routes(target) | _routes(finding))
        target["mergedOccurrences"] = target.get("mergedOccurrences", 1) + 1
    return merged


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
    return _deduplicate_findings(findings), deferred
