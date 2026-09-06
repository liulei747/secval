"""P2-9 报告按范围归组：scope 子任务覆盖情况单独呈现。"""

from secval.services.audit_report import export_audit_report


def _task_with_workers():
    return {
        "id": "t", "status": "needs_review", "model_requests": [],
        "team_deliveries": ["agent-3"],
        "agent_tasks": [
            {"id": "agent-1", "role": "baseline", "status": "completed",
             "assignment": {"title": "独立基线审计"}, "evidence": {}},
            {"id": "agent-2", "role": "scope", "status": "failed",
             "assignment": {"title": "范围调查：orders"}, "evidence": {}, "result": None},
            {"id": "agent-3", "role": "scope", "status": "completed",
             "assignment": {"title": "范围调查：billing"},
             "result": {"summary": "billing 完成", "questions": [{}, {}]},
             "evidence": {}},
        ],
    }


def test_scope_coverage_groups_and_gaps():
    body = export_audit_report(_task_with_workers())
    groups = body["scopeCoverage"]["groups"]
    assert [g["scope"] for g in groups] == ["orders", "billing"]
    failed = next(g for g in groups if g["scope"] == "orders")
    assert failed["delivered"] is False and failed["summary"] is None
    done = next(g for g in groups if g["scope"] == "billing")
    assert done["delivered"] is True and done["questionCount"] == 2
    assert "不代表该范围安全" in body["scopeCoverage"]["note"]
    # 失败的 scope 子任务同时出现在既有缺口列表。
    assert any(item["id"] == "agent-2" for item in body["coverage"]["deferred"])
