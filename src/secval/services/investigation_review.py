"""追加核查历史并推进问题状态，保留旧事件中的对象不变。"""

from dataclasses import asdict


def apply_review(investigations, review, step):
    updated = []
    record = None
    for item in investigations:
        if item["id"] != review.investigation_id:
            updated.append(item)
            continue
        history = item.get("reviews", [])
        record = {
            **asdict(review), "revision": len(history) + 1, "step": step,
            "method": "static_same_agent", "independently_validated": False,
        }
        updated.append({**item, "status": review.outcome, "reviews": [*history, record]})
    if record is None:
        raise ValueError("调查问题不存在")
    return updated, record
