from secval.services.audit_markdown import render_audit_markdown


def test_markdown_renders_findings_as_report_sections():
    report = {
        "taskId": "task-1", "status": "needs_review", "summary": "审计摘要",
        "findings": [{
            "title": "缺少对象归属检查", "summary": "普通用户可读取其他订单",
            "investigation_id": "investigation-1",
            "severity": {"level": "high"}, "confidence": {"level": "high"},
            "taxonomy": {"cwe": ["CWE-639"]},
            "rootControlLocation": {"path": "orders.py", "startLine": 42},
            "rootCause": {"summary": "仅按订单编号查询"},
            "attackPath": {"summary": "用户修改订单编号后读取数据"},
            "validation": {"assessment": "独立源码复核支持"},
            "remediation": "同时校验订单所有者",
        }],
        "completion": {"state": "recorded_checks_closed", "completeSecurityAudit": False,
                       "pendingReasons": []},
        "notice": "静态分析需复核",
    }

    body = render_audit_markdown(report)

    assert "## 安全发现" in body
    assert "### 1. 缺少对象归属检查" in body
    assert "`orders.py:42`" in body
    assert "#### 攻击路径" in body
    assert "#### 修复建议" in body


def test_markdown_uses_final_validation_state_and_hides_promoted_candidate():
    report = {
        "taskId": "task-3", "status": "needs_review",
        "summary": "旧草稿：独立复核未完成",
        "unknowns": ["独立复核子任务未产出", "部署配置不可见"],
        "findings": [{
            "title": "IDOR", "investigation_id": "investigation-1",
            "severity": {"level": "high"}, "confidence": {"level": "high"},
            "taxonomy": {"cwe": ["CWE-639"]}, "rootControlLocation": {},
            "rootCause": {}, "attackPath": {}, "validation": {"assessment": "支持"},
        }],
        "candidateDetails": [{"title": "IDOR", "investigation_id": "investigation-1"}],
        "completion": {"state": "partial_report", "completeSecurityAudit": False},
    }

    body = render_audit_markdown(report)

    assert "经独立静态复核确认 1 条正式安全发现" in body
    assert "旧草稿" not in body
    assert "## 待独立复核候选" not in body
    assert "独立复核子任务未产出" not in body
    assert "部署配置不可见" in body


def test_markdown_distinguishes_candidates_from_validated_findings():
    report = {
        "taskId": "task-2", "status": "needs_review", "summary": "部分报告",
        "findings": [],
        "candidateDetails": [{"title": "待复核上传问题", "summary": "尚未独立复核",
                              "investigation_id": "investigation-1",
                              "severity": {"level": "medium"}}],
        "completion": {"state": "partial_report", "completeSecurityAudit": False,
                       "pendingReasons": ["仍有待复核候选"]},
    }

    body = render_audit_markdown(report)

    assert "没有通过独立静态复核的正式发现" in body
    assert "## 待独立复核候选" in body
    assert "仍有待复核候选" in body
