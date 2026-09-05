"""从持久化任务构造可移交报告，不执行模型、不升级候选、不修改历史。"""

from copy import deepcopy
from dataclasses import asdict
from secval.models.audit_contracts import CodeEvidence

from secval.services.file_review_coverage import file_review_coverage
from secval.services.report_coverage import report_coverage, report_completion


def export_audit_report(task):
    report = deepcopy(task.get("report") or task.get("draft_report") or {})
    boundaries = deepcopy(task.get("security_boundaries", []))
    investigations = deepcopy(task.get("investigations", []))
    validations = deepcopy(task.get("independent_reviews", []))
    coverage = report.get("coverage") or report_coverage(boundaries, investigations, validations, task.get("baseline"))
    coverage["complete"] = False
    coverage["files"] = file_review_coverage(task.get("source_inventory"),
        task.get("scope", {}).get("source_snapshot_id"), task.get("file_reviews", []))
    if task.get("status") != "needs_review":
        coverage["limitations"].append("任务未提交最终报告；此导出只包含当前已保存进度")
    supplied = task.get("supplied_threat_model", "")
    generated = (task.get("threat_model_history") or [None])[-1]
    workers = task.get("agent_tasks", [])
    # 子任务失败或结果未交付都属于缺口，不能因为最终报告存在而消失。
    for worker in workers:
        if worker.get("status") != "completed" or worker["id"] not in task.get("team_deliveries", []):
            coverage["deferred"].append({"id": worker["id"], "reason": "子任务未完成或结果尚未交付主调查"})
    return {
        "documentType": "secval.audit-report", "schemaVersion": "1.0", "taskId": task["id"],
        "status": task.get("status"), "phase": task.get("phase"),
        "continuation": {"parentTaskId": task.get("parent_task_id"),
                         "parentReportSubmitted": task.get("parent_report_submitted", False),
                         "priorModelCalls": task.get("prior_model_calls", 0),
                         "currentModelCalls": task.get("model_calls", 0)},
        "budget": {"maxModelCalls": task.get("max_steps"), "maxSeconds": task.get("max_seconds", 300),
                   "note": "各阶段共享；时长在请求边界检查，不强行终止已发送请求，不是费用上限"},
        "modelRequests": deepcopy(task.get("model_requests", [])),
        "parallelAgents": task.get("parallel_agents", 1),
        "agentTasks": [{**{key: deepcopy(worker.get(key)) for key in
                        ("id", "role", "assignment", "status", "calls", "prior_calls", "reused_result", "elapsed_seconds", "stop_reason", "result")},
                        "progressResults": deepcopy(worker.get("progress_results", [])),
                        "codeEvidence": [asdict(CodeEvidence.from_read(row)) for row in worker.get("evidence", {}).values()]}
                       for worker in workers],
        "modelRequestNote": "仅本任务已保存的请求统计；取消或进程中断可能缺少尾部耗时，不能视为未调用或未计费。响应返回不等于动作校验通过。",
        "objective": task.get("objective"),
        "scope": deepcopy(task.get("scope") or {
            "repository_id": task.get("repository_id"), "snapshot_id": task.get("snapshot_id"),
            "scope_paths": task.get("scope_paths", []), "limitations": ["旧任务缺少范围预检"],
        }),
        "securityContext": task.get("security_context", ""),
        "threatModel": {"summary": supplied} if supplied else deepcopy(generated),
        "generatedThreatModel": deepcopy(generated),
        "baseline": deepcopy(task.get("baseline")),
        "summary": report.get("summary", "未生成最终摘要"),
        "findings": report.get("findings", []) if task.get("report") else [],
        "hypotheses": report.get("hypotheses", []),
        "candidateDetails": deepcopy(task.get("finding_detail_history", [])),
        "boundaries": boundaries, "investigations": investigations,
        "independentReviews": validations, "coverage": coverage,
        "completion": report_completion(task, coverage),
        "unknowns": report.get("unknowns", []),
        "codeEvidence": deepcopy(task.get("codeEvidence", [])),
        "readCoverage": deepcopy(task.get("read_coverage")),
        "fileReviews": deepcopy(task.get("file_reviews", [])),
        "stopReason": task.get("stop_reason"), "error": task.get("error"),
        "notice": "静态分析结果均需复核；导出不表示完整覆盖或动态复现。可能包含敏感源码，请勿公开上传。",
    }
