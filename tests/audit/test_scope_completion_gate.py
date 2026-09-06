"""P1-8：范围子任务未交付时，报告完成状态不得记为 recorded_checks_closed。"""

from secval.services.audit_report import export_audit_report


def _task(scope_status, delivered):
    return {
        "id": "t", "status": "needs_review", "model_requests": [],
        "report": {"summary": "s", "hypotheses": [], "unknowns": []},
        "security_boundaries": [{"id": "b1"}],
        "investigations": [{"id": "i1", "status": "refuted", "boundary_id": "b1"}],
        "team_deliveries": ["agent-2"] if delivered else [],
        "agent_tasks": [
            {"id": "agent-2", "role": "scope", "status": scope_status,
             "assignment": {"title": "范围调查：orders"}, "evidence": {},
             "result": {"summary": "ok", "questions": []} if delivered else None},
        ],
    }


def test_failed_scope_blocks_recorded_checks_closed():
    body = export_audit_report(_task("failed", False))
    completion = body["completion"]
    assert completion["state"] == "partial_report"
    assert any("范围调查" in reason for reason in completion["pendingReasons"])


def test_delivered_scope_does_not_block():
    body = export_audit_report(_task("completed", True))
    completion = body["completion"]
    assert not any("范围调查" in reason for reason in completion["pendingReasons"])
