"""从持久化任务构造可移交报告，不执行模型、不升级候选、不修改历史。"""

from copy import deepcopy
from dataclasses import asdict
from secval.models.audit_contracts import CodeEvidence

from secval.services.file_review_coverage import file_review_coverage
from secval.services.report_coverage import report_coverage, report_completion


def export_audit_report(task):
    report = deepcopy(task.get("report") or task.get("draft_report") or {})
    # 任务级 token 汇总：仅累计各请求记录中供应商上报的整数用量；
    # 缺失字段不计 0，防止把未上报当作零消耗。
    totals = {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0}
    counted = {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0}
    for row in task.get("model_requests", []):
        for key in totals:
            value = row.get(key)
            if type(value) is int and value >= 0:
                totals[key] += value
                counted[key] += 1
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
        durable_probe = (worker.get("mode") == "prefill_path_probe"
                         and worker.get("status") == "completed")
        if (worker.get("status") != "completed"
                or (worker["id"] not in task.get("team_deliveries", []) and not durable_probe)):
            coverage["deferred"].append({"id": worker["id"], "reason": "子任务未完成或结果尚未交付主调查"})
    # P2-9：按范围归组呈现 scope 子任务覆盖情况；范围名来自分派时的 assignment 标题。
    scope_groups = []
    for worker in workers:
        if worker.get("role") != "scope":
            continue
        assignment = worker.get("assignment") or {}
        title = assignment.get("title", "")
        scope_name = title.split("：", 1)[1] if "：" in title else title
        result = worker.get("result") or {}
        completed = worker.get("status") == "completed" and worker["id"] in task.get("team_deliveries", [])
        scope_groups.append({"workerId": worker["id"], "scope": scope_name,
                             "status": worker.get("status"), "delivered": completed,
                             "summary": result.get("summary") if completed else None,
                             "questionCount": len(result.get("questions") or []) if completed else 0})
    scope_coverage = {"groups": scope_groups,
                      "note": "范围覆盖来自自动拆分的 scope 子任务；失败或未交付即缺口，不代表该范围安全"}
    coverage["scopeCoverage"] = scope_coverage
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
        "tokenUsage": {"promptTokens": totals["prompt_tokens"],
                       "completionTokens": totals["completion_tokens"],
                       "totalTokens": totals["total_tokens"],
                       "requestsCountedBySupplier": counted["total_tokens"],
                       "requestsTotal": len(task.get("model_requests", [])),
                       "note": "仅供应商上报的整数用量被累计；缺失字段的请求不计入对应合计"},
        "parallelAgents": task.get("parallel_agents", 1),
        "agentTasks": [{**{key: deepcopy(worker.get(key)) for key in
                        ("id", "role", "assignment", "status", "calls", "prior_calls", "reused_result", "elapsed_seconds", "stop_reason", "result")},
                        "progressResults": deepcopy(worker.get("progress_results", [])),
                        "codeEvidence": [asdict(CodeEvidence.from_read(row)) for row in worker.get("evidence", {}).values()]}
                       for worker in workers],
        "scopeCoverage": scope_coverage,
        "modelRequestNote": "仅本任务已保存的请求统计；取消或进程中断可能缺少尾部耗时，不能视为未调用或未计费。响应返回不等于动作校验通过。",
        "objective": task.get("objective"),
        "scope": deepcopy(task.get("scope") or {
            "repository_id": task.get("repository_id"), "snapshot_id": task.get("snapshot_id"),
            "scope_paths": task.get("scope_paths", []), "limitations": ["旧任务缺少范围预检"],
        }),
        "graphQuery": {
            "repositoryId": task.get("repository_id"),
            "snapshotId": task.get("snapshot_id"),
            "indexRunId": (task.get("scope") or {}).get("index_run_id"),
            "pageHint": "在 /graph 页面选择同一仓库/快照/批次即可人工核对关系线索",
        },
        "securityContext": task.get("security_context", ""),
        "threatModel": {"summary": supplied} if supplied else deepcopy(generated),
        "generatedThreatModel": deepcopy(generated),
        "baseline": deepcopy(task.get("baseline")),
        "kernelRuntime": deepcopy(task.get("kernel_runtime")),
        "legacyReportReadOnly": task.get("legacy_report_read_only", False),
        "summary": report.get("summary", "未生成最终摘要"),
        "findings": report.get("findings", []) if task.get("report") else [],
        "hypotheses": report.get("hypotheses", []),
        "candidateDetails": deepcopy(task.get("finding_detail_history", [])),
        "discoveryPackets": deepcopy(task.get("discovery_packets", [])),
        "entryInventory": deepcopy(task.get("entry_inventory", [])),
        "sinkInventory": deepcopy(task.get("sink_inventory", [])),
        "pathSketches": deepcopy(task.get("path_sketches", [])),
        "validationPackets": deepcopy(task.get("validation_packets", [])),
        "pathValidations": deepcopy(task.get("path_validations", [])),
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
