"""从已保存事实生成可分页的待办视图；不是模型自己声明的完成率。"""

from secval.services.file_review_coverage import file_review_coverage
from secval.services.report_coverage import report_coverage


def audit_progress(task, offset=0):
    coverage = report_coverage(task.get("security_boundaries", []), task.get("investigations", []),
                               task.get("independent_reviews", []), task.get("baseline"))
    files = file_review_coverage(task.get("source_inventory"),
                                task.get("scope", {}).get("source_snapshot_id"), task.get("file_reviews", []))
    remaining = files["remaining"]
    pending = coverage["deferred"]
    end = offset + 20
    return {
        "complete": False,
        "pendingFiles": remaining[offset:end], "pendingInvestigations": pending[offset:end],
        "pendingFileCount": len(remaining) if files["available"] else None,
        "pendingInvestigationCount": len(pending),
        "excludedFileCount": len(files.get("excluded", [])) if files["available"] else None,
        "next_offset": end if end < max(len(remaining), len(pending)) else None,
        "hasStructuredThreatModel": bool(task.get("threat_model_history")),
        "remainingModelCalls": max(0, task["max_steps"] - task.get("model_calls", 0)),
        "limitations": [*coverage["limitations"], *files["limitations"],
                        "待办为空不证明审计完整；未知依赖、未识别入口和排除项仍需复核"],
    }
