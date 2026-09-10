"""Capture a completed real audit and its compact comparison metadata."""

import argparse
import json
import urllib.request
from datetime import datetime
from pathlib import Path


def fetch(url):
    with urllib.request.urlopen(url, timeout=30) as response:
        return json.load(response)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("task_id")
    parser.add_argument("--api", default="http://127.0.0.1:8000")
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    task = fetch(f"{args.api}/api/audits/{args.task_id}")
    report = fetch(f"{args.api}/api/audits/{args.task_id}/report")
    if task.get("execution_active") or task.get("stop_reason") != "report_submitted":
        raise SystemExit("audit has not submitted a terminal report")
    output = Path(args.output)
    output.mkdir(parents=True, exist_ok=True)
    (output / "report.json").write_text(
        json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    started = datetime.fromisoformat(task["started_at"])
    finished = datetime.fromisoformat(task["finished_at"])
    requests = task.get("model_requests", [])
    coverage = report.get("coverage", {})
    reviews = report.get("independentReviews", [])
    metrics = {
        "task_id": args.task_id,
        "repository_id": task.get("repository_id"),
        "snapshot_id": task.get("snapshot_id"),
        "status": task.get("status"),
        "phase": task.get("phase"),
        "stop_reason": task.get("stop_reason"),
        "completion_state": report.get("completion", {}).get("state"),
        "complete_security_audit": report.get("completion", {}).get("completeSecurityAudit"),
        "elapsed_seconds": (finished - started).total_seconds(),
        "model_calls": task.get("model_calls"),
        "token_usage": report.get("tokenUsage"),
        "request_statuses": {
            status: sum(row.get("status") == status for row in requests)
            for status in sorted({row.get("status") for row in requests})
        },
        "path_sketches": len(task.get("path_sketches", [])),
        "path_validations": len(task.get("path_validations", [])),
        "candidate_details": len(task.get("finding_detail_history", [])),
        "independent_reviews": len(task.get("independent_reviews", [])),
        "review_outcomes": {
            outcome: sum(row.get("outcome") == outcome for row in reviews)
            for outcome in ("supported", "refuted", "inconclusive")
        },
        "deferred_checks": len(coverage.get("deferred", [])),
        "unresolved_checks": len(coverage.get("unresolved", [])),
        "remaining_files": len((coverage.get("files") or {}).get("remaining", [])),
        "excluded_files": len((coverage.get("files") or {}).get("excluded", [])),
        "formal_findings": sum(
            row.get("status") == "static_supported_needs_review"
            for row in report.get("findings", [])
        ),
        "kernel_runtime_present": task.get("kernel_runtime") is not None,
        "legacy_report_read_only": task.get("legacy_report_read_only"),
    }
    (output / "metrics.json").write_text(
        json.dumps(metrics, ensure_ascii=False, indent=2), encoding="utf-8"
    )


if __name__ == "__main__":
    main()
