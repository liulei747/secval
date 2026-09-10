"""报告生成不等于检查项收口，空结果也不表示安全。"""

from secval.services.report_coverage import report_completion, report_coverage


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


def test_unfinished_discovery_and_path_queues_block_closure():
    task = recorded_task()
    task.update(
        discovery_packets=[{"id": "entry-1"}, {"id": "sink-1"}],
        agent_tasks=[{"id": "agent-1", "mode": "prefill_path_probe", "status": "completed"}],
        path_sketches=[{"id": "path-1", "status": "queued_for_validation"}],
        validation_packets=[{"id": "validation-1", "status": "queued"}],
    )
    result = report_completion(task, {"deferred": [],
        "files": {"available": True, "remaining": [], "excluded": []}})
    assert result["state"] == "partial_report"
    assert any("发现包" in reason for reason in result["pendingReasons"])
    assert any("路径验证包" in reason for reason in result["pendingReasons"])
    assert any("路径草稿" in reason for reason in result["pendingReasons"])


def test_terminal_path_ledger_does_not_add_queue_reasons():
    task = recorded_task()
    task.update(
        discovery_packets=[{"id": "entry-1"}],
        agent_tasks=[{"id": "agent-1", "mode": "prefill_path_probe", "status": "completed"}],
        path_sketches=[{"id": "path-1", "status": "refuted"}],
        validation_packets=[{"id": "validation-1", "status": "completed"}],
    )
    result = report_completion(task, {"deferred": [],
        "files": {"available": True, "remaining": [], "excluded": []}})
    assert not any("发现包" in reason or "路径验证包" in reason or "路径草稿" in reason
                   for reason in result["pendingReasons"])


def test_baseline_question_is_linked_only_by_exact_normalized_route():
    boundaries = [{"id": "b1", "entry": "GET /api/accounts/{accountId}"},
                  {"id": "b2", "entry": "GET /api/accounts/settings"}]
    investigations = [{"id": "i1", "boundary_id": "b1", "question": "check ownership",
                       "status": "refuted", "baseline_question_ids": []},
                      {"id": "i2", "boundary_id": "b2", "question": "check settings",
                       "status": "refuted", "baseline_question_ids": []}]
    baseline = {"questions": [{"id": "q1", "question": "GET /api/accounts/{id} 是否越权"},
                              {"id": "q2", "question": "整体访问控制是否缺失",
                               "outcome": "inconclusive", "evidence_ids": ["read-1"]}]}
    coverage = report_coverage(boundaries, investigations, [], baseline)
    assert investigations[0]["baseline_question_ids"] == ["q1"]
    assert investigations[1]["baseline_question_ids"] == []
    assert coverage["deferred"] == []
    assert coverage["unresolved"] == [{"id": "q2", "reason": "基线问题未关联主调查"}]


def test_completed_inconclusive_review_is_unresolved_but_not_pending():
    coverage = report_coverage(
        [{"id": "b1"}],
        [{"id": "i1", "boundary_id": "b1", "status": "supported"}],
        [{"investigation_id": "i1", "outcome": "inconclusive",
          "assessment": "根因成立但部署影响未知", "limitations": ["部署不可见"]}],
    )
    assert coverage["deferred"] == []
    assert coverage["unresolved"][0]["id"] == "i1"


def test_failed_inconclusive_review_remains_pending():
    coverage = report_coverage(
        [{"id": "b1"}],
        [{"id": "i1", "boundary_id": "b1", "status": "supported"}],
        [{"investigation_id": "i1", "outcome": "inconclusive",
          "error": "复核请求失败"}],
    )
    assert coverage["deferred"] == [{"id": "i1", "reason": "独立上下文复核未完成"}]
