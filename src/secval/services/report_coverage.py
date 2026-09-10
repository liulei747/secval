"""由任务事实生成报告缺口；模型无权把未完成工作标记为完整覆盖。"""

import re


def _routes(text):
    return {re.sub(r"\{[^}/]+\}", "{}", route.rstrip(".,;:，。；：）)"))
            for route in re.findall(r"/api/[A-Za-z0-9_{}./*-]+", text or "")}


def link_baseline_questions_by_routes(boundaries, investigations, baseline):
    """Link baseline provenance only when an exact normalized API route overlaps."""
    boundary_by_id = {row["id"]: row for row in boundaries}
    linked = {link for item in investigations for link in item.get("baseline_question_ids", [])}
    for question in (baseline or {}).get("questions", []):
        if question["id"] in linked:
            continue
        question_routes = _routes(question.get("question", ""))
        if not question_routes:
            continue
        for item in investigations:
            boundary = boundary_by_id.get(item.get("boundary_id"), {})
            candidate_routes = _routes(" ".join((item.get("question", ""), boundary.get("entry", ""))))
            if question_routes & candidate_routes:
                item["baseline_question_ids"] = list(dict.fromkeys(
                    [*item.get("baseline_question_ids", []), question["id"]]))
                linked.add(question["id"])
                break


def report_coverage(boundaries, investigations, validations=(), baseline=None):
    link_baseline_questions_by_routes(boundaries, investigations, baseline)
    investigated = {item["boundary_id"] for item in investigations}
    reviewed = {item["investigation_id"] for item in validations}
    deferred, unresolved = [], []
    linked = {link for item in investigations for link in item.get("baseline_question_ids", [])}
    for question in (baseline or {}).get("questions", []):
        if question["id"] not in linked:
            target = unresolved if (question.get("outcome") in {"supported", "refuted", "inconclusive"}
                                    and question.get("evidence_ids")) else deferred
            target.append({"id": question["id"], "reason": "基线问题未关联主调查"})
    for boundary in boundaries:
        if boundary["id"] not in investigated:
            deferred.append({"id": boundary["id"], "reason": "边界尚未形成调查问题"})
    for item in investigations:
        status = item.get("status", "open")
        if status == "open":
            deferred.append({"id": item["id"], "reason": "调查尚未形成终态"})
        elif status == "inconclusive":
            unresolved.append({"id": item["id"], "reason": "调查证据不足，已记录为不确定"})
        elif status == "supported" and item["id"] not in reviewed:
            deferred.append({"id": item["id"], "reason": "静态候选尚未独立上下文复核"})
    for item in validations:
        if item["outcome"] == "inconclusive":
            target = deferred if item.get("error") else unresolved
            reason = ("独立上下文复核未完成" if item.get("error")
                      else "独立上下文复核证据不足，已记录为不确定")
            target.append({"id": item["investigation_id"], "reason": reason})
    return {
        "complete": False,
        "boundary_count": len(boundaries), "investigation_count": len(investigations),
        "deferred": deferred, "unresolved": unresolved,
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
    discovery = task.get("discovery_packets", [])
    probe_workers = [row for row in task.get("agent_tasks", [])
                     if row.get("mode") == "prefill_path_probe"]
    if discovery and (len(probe_workers) < len(discovery)
                      or any(row.get("status") != "completed" for row in probe_workers)):
        reasons.append("仍有入口、敏感操作或配置发现包未成功处理")
    path_packets = task.get("validation_packets", [])
    if any(row.get("status") != "completed" for row in path_packets):
        reasons.append("仍有路径验证包未完成")
    sketches = task.get("path_sketches", [])
    terminal = {"supported", "refuted", "inconclusive"}
    if any(row.get("status") not in terminal for row in sketches):
        reasons.append("仍有路径草稿未形成可复核结论")
    if coverage.get("deferred"):
        reasons.append("仍有未收口的调查、基线问题或候选复核")
    scope_groups = (coverage.get("scopeCoverage") or {}).get("groups") or []
    missing_scope = [g for g in scope_groups
                     if not g.get("delivered")]
    if missing_scope:
        reasons.append("仍有范围调查子任务未完成或未交付："
                       + ", ".join(g.get("scope", "") or g.get("workerId", "")
                                   for g in missing_scope))
    files = coverage.get("files", {})
    if not files.get("available"):
        reasons.append("缺少固定源码清单，不能判断文件审阅是否收口")
    else:
        if files.get("remaining"):
            reasons.append("仍有未完成安全审阅声明的文件")
        if files.get("excluded"):
            reasons.append("范围内存在未采集文件，不能把排除当作已检查")
    if (task.get("independent_baseline", False)
            and (task.get("baseline") or {}).get("status") != "submitted_partial"):
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
