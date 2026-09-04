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
