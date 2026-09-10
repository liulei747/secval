"""仅在固定源码清单内核对安全审阅声明，不将读取或排除自动视为完成。"""

from secval.code_processing.repository_scan import is_supported_source
from secval.models.audit_scope import is_executable_descriptor


def file_review_coverage(inventory, source_id, reviews, approved_paths=()):
    if inventory is None:
        return {"available": False, "remaining": [], "limitations": ["缺少绑定的源码清单"]}
    latest = {item["path"]: item for item in reviews}
    reviewed, remaining, excluded, not_applicable = [], [], [], []
    approved = set(approved_paths or ())
    for row in inventory:
        if row["status"] != "captured":
            excluded.append({"path": row["path"], "reason": row["status"]})
            continue
        if not (is_supported_source(row["path"]) or is_executable_descriptor(row["path"])
                or row["path"] in approved):
            not_applicable.append(row["path"])
            continue
        item = latest.get(row["path"])
        if (item and item["source_snapshot_id"] == source_id and item["content_sha256"] == row["digest"]
                and item["status"] == "reviewed_static"):
            reviewed.append(row["path"])
        else:
            remaining.append(row["path"])
    return {"available": True, "reviewed_static": reviewed, "remaining": remaining,
            "excluded": excluded, "not_applicable": not_applicable,
            "semantically_verified": False,
            "limitations": ["基于模型安全审阅声明核对，非独立证明；排除项不算已审计"]}
