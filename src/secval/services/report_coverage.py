"""由任务事实生成报告缺口；模型无权把未完成工作标记为完整覆盖。"""


def report_coverage(boundaries, investigations, validations=(), baseline=None):
    investigated = {item["boundary_id"] for item in investigations}
    reviewed = {item["investigation_id"] for item in validations}
    deferred = []
    linked = {link for item in investigations for link in item.get("baseline_question_ids", [])}
    for question in (baseline or {}).get("questions", []):
        if question["id"] not in linked:
            deferred.append({"id": question["id"], "reason": "基线问题尚未接续调查"})
    for boundary in boundaries:
        if boundary["id"] not in investigated:
            deferred.append({"id": boundary["id"], "reason": "边界尚未形成调查问题"})
    for item in investigations:
        status = item.get("status", "open")
        if status in {"open", "inconclusive"}:
            deferred.append({"id": item["id"], "reason": "待调查或证据不足"})
        elif status == "supported" and item["id"] not in reviewed:
            deferred.append({"id": item["id"], "reason": "静态候选尚未独立上下文复核"})
    for item in validations:
        if item["outcome"] == "inconclusive":
            deferred.append({"id": item["investigation_id"], "reason": "独立上下文复核证据不足"})
    return {
        "complete": False,
        "boundary_count": len(boundaries), "investigation_count": len(investigations),
        "deferred": deferred,
        "rejected": list(dict.fromkeys(
            [item["id"] for item in investigations if item.get("status") == "refuted"]
            + [item["investigation_id"] for item in validations if item["outcome"] == "refuted"]
        )),
        "limitations": ["尚无完整安全审计范围分母，不能宣称全项目审计完成",
                        "文件阅读量不等于安全审计覆盖；配置、依赖及动态行为仍可能缺失"],
    }


def report_completion(task, coverage):
    """报告提交与待办收口是两件事；均不代表完整安全审计。"""
    reasons = []
    if coverage.get("deferred"):
        reasons.append("仍有未收口的调查、基线问题或候选复核")
    files = coverage.get("files", {})
    if not files.get("available"):
        reasons.append("缺少固定源码清单，不能判断文件审阅是否收口")
    else:
        if files.get("remaining"):
            reasons.append("仍有未完成安全审阅声明的文件")
        if files.get("excluded"):
            reasons.append("范围内存在未采集文件，不能把排除当作已检查")
    if task.get("independent_baseline", False):
        if (task.get("baseline") or {}).get("status") != "submitted_partial":
            reasons.append("独立基线尚未提交调查问题")
    if not task.get("threat_model_history"):
        reasons.append("尚未建立结构化威胁模型")
    if not task.get("security_boundaries") or not task.get("investigations"):
        reasons.append("缺少已登记的边界或调查，不能将空记录视为完成")
    submitted = task.get("status") == "needs_review" and bool(task.get("report"))
    if not submitted:
        state = "not_submitted"
    elif reasons:
        state = "partial_report"
    else:
        state = "recorded_checks_closed"
    return {"state": state, "reportSubmitted": submitted, "pendingReasons": reasons,
            "completeSecurityAudit": False,
            "note": "仅核对已登记检查项；未识别入口、外部依赖和语义误判仍可能存在，不证明项目安全"}
