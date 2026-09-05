"""报告生成不等于检查项收口，空结果也不表示安全。"""

from secval.services.report_coverage import report_completion


def recorded_task():
    return {"status": "needs_review", "report": {"summary": "测试报告"},
            "independent_baseline": True, "baseline": {"status": "submitted_partial"},
            "threat_model_history": [{"summary": "测试"}],
            "security_boundaries": [{"id": "b"}], "investigations": [{"id": "i"}]}


def test_empty_records_cannot_be_marked_closed():
    result = report_completion({"status": "needs_review", "report": {"summary": "空报告"}},
                               {"deferred": [], "files": {"available": True, "remaining": []}})
    assert result["state"] == "partial_report"
    assert result["completeSecurityAudit"] is False


def test_pending_work_produces_partial_report():
    result = report_completion(recorded_task(), {"deferred": [{"id": "i"}],
        "files": {"available": True, "remaining": ["Test.java"], "excluded": [{"path": "missing"}]}})
    assert result["state"] == "partial_report"
    assert len(result["pendingReasons"]) == 3


def test_recorded_checks_closed_still_does_not_claim_full_audit():
    result = report_completion(recorded_task(), {"deferred": [],
        "files": {"available": True, "remaining": [], "excluded": []}})
    assert result["state"] == "recorded_checks_closed"
    assert result["completeSecurityAudit"] is False


def test_draft_is_not_final_report():
    task = recorded_task()
    task["status"] = "failed"
    assert report_completion(task, {})["state"] == "not_submitted"


def test_closed_report_cannot_be_resumed_as_partial():
    from unittest.mock import MagicMock

    import pytest

    from secval.services.audit_service import AuditService

    task = recorded_task()
    task.update(id="task", source_inventory=[], scope={"source_snapshot_id": "source"})
    task["report"]["coverage"] = {"complete": False, "deferred": [], "limitations": []}
    store = MagicMock()
    store.get.return_value = task
    factory = MagicMock()
    service = AuditService(store, MagicMock(), factory, MagicMock())
    with pytest.raises(ValueError, match="部分报告"):
        service.resume("task", allow_remote_code=True)
    factory.assert_not_called()
