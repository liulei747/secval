"""从已保存事实生成可分页的待办视图；不是模型自己声明的完成率。"""

from secval.models.read_coverage import read_coverage
from secval.services.file_review_coverage import file_review_coverage
from secval.services.report_coverage import report_coverage


def request_budget_note(task):
    """提供当前预算，不让模型只能依靠旧的进度查询估计剩余额度。"""
    remaining = max(0, task["max_steps"] - task.get("model_calls", 0))
    if task.get("parallel_agents", 1) > 1:
        return (f"当前全队最多剩余{remaining}次模型调用（包含即将发起的本次请求，其他Agent可能同时使用）。"
                "优先核实已回传问题与候选详情，保留独立复核预算；未知项不得强行确认。")
    return (
        f"后端执行提示：本次请求之后最多还可调用模型{remaining}次，独立复核也使用同一预算。"
        "优先完成当前目标中已有证据的调查、反证和候选详情，为独立复核预留调用。"
        "不要为同一控制反复建立重复调查；缺失依赖保留为未知，不推测实现。"
        "预算不足时可提交部分报告并明确缺口，不能宣称已完成全部审计。"
    )


def audit_progress(task, offset=0):
    coverage = report_coverage(task.get("security_boundaries", []), task.get("investigations", []),
                               task.get("independent_reviews", []), task.get("baseline"))
    files = file_review_coverage(task.get("source_inventory"),
                                 task.get("scope", {}).get("source_snapshot_id"),
                                 task.get("file_reviews", []), task.get("approved_config_paths", []))
    remaining = files["remaining"]
    pending = coverage["deferred"]
    end = offset + 20
    # [SECVAL-RECEIPT] 如实反馈"哪些文件已整文件读完"，而不是只给阅读字数。
    # 依据：模型可能只搜索到片段就声称已审阅；这里把后端已确认的完整读取
    # 清单显式回给模型，使它无法把"看到过片段"当成"审阅过文件"。
    fully_read = sorted({row["path"] for row in read_coverage(task.get("evidence", {}))["objects"]
                         if row["kind"] == "file" and row["fully_read"]})
    return {
        "complete": False,
        "pendingFiles": remaining[offset:end], "pendingInvestigations": pending[offset:end],
        "pendingFileCount": len(remaining) if files["available"] else None,
        "pendingInvestigationCount": len(pending),
        "excludedFileCount": len(files.get("excluded", [])) if files["available"] else None,
        "next_offset": end if end < max(len(remaining), len(pending)) else None,
        "hasStructuredThreatModel": bool(task.get("threat_model_history")),
        "remainingModelCalls": max(0, task["max_steps"] - task.get("model_calls", 0)),
        "fullyReadFiles": fully_read[offset:end],
        "fullyReadFileCount": len(fully_read),
        "receiptNote": "只有列在fullyReadFiles中的文件才被后端确认完整读取；"
                       "登记文件审阅(record_file_review)必须使用这些文件，搜索结果不算。",
        "limitations": [*coverage["limitations"], *files["limitations"],
                        "待办为空不证明审计完整；未知依赖、未识别入口和排除项仍需复核"],
    }
