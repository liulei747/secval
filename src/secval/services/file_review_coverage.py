"""仅在固定源码清单内核对安全审阅声明，不将读取或排除自动视为完成。"""


def file_review_coverage(inventory, source_id, reviews):
    if inventory is None:
        return {"available": False, "remaining": [], "limitations": ["缺少绑定的源码清单"]}
    latest = {item["path"]: item for item in reviews}
    reviewed, remaining, excluded = [], [], []
    for row in inventory:
        if row["status"] != "captured":
            excluded.append({"path": row["path"], "reason": row["status"]})
            continue
        item = latest.get(row["path"])
        if (item and item["source_snapshot_id"] == source_id and item["content_sha256"] == row["digest"]
                and item["status"] == "reviewed_static"):
            reviewed.append(row["path"])
        else:
            remaining.append(row["path"])
    return {"available": True, "reviewed_static": reviewed, "remaining": remaining, "excluded": excluded,
            "semantically_verified": False,
            "limitations": ["基于模型安全审阅声明核对，非独立证明；排除项不算已审计"]}
