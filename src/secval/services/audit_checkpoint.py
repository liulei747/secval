"""恢复已落盘的只读调查边界，不恢复过期 PIT 或假定未返回请求的执行结果。"""

from copy import deepcopy

from secval.services.audit_context import compact_context, context_size

STATE_FIELDS = ("evidence", "events", "security_boundaries", "threat_model_history",
                "investigations", "finding_detail_history", "file_reviews", "baseline",
                "read_coverage", "codeEvidence", "correction_count", "team_deliveries")


def checkpoint(messages, state, *, phase="investigation"):
    if phase not in {"baseline", "investigation"}:
        raise ValueError("不支持的检查点阶段")
    return {"version": 1, "phase": phase, "messages": deepcopy(messages),
            "state": {key: deepcopy(state[key]) for key in STATE_FIELDS if key in state}}


def restore_checkpoint(parent, scope, inventory):
    saved = parent.get("checkpoint")
    if not isinstance(saved, dict) or saved.get("version") != 1 or saved.get("phase") not in {"baseline", "investigation"}:
        raise ValueError("任务没有可恢复的调查检查点")
    previous = parent.get("scope", {})
    for key in ("repository_id", "snapshot_id", "source_snapshot_id", "index_run_id"):
        if not previous.get(key) or previous[key] != scope.get(key):
            raise ValueError("源码快照或索引批次已改变/未绑定，不能混用旧证据续跑")
    for key in ("scope_paths", "approved_config_paths"):
        if previous.get(key, []) != scope.get(key, []):
            raise ValueError("续跑范围或配置授权与检查点不一致")
    if inventory is None or parent.get("source_inventory") != inventory:
        raise ValueError("源码清单与检查点不一致，不能续跑")
    if not isinstance(saved.get("messages"), list) or not saved["messages"]:
        raise ValueError("检查点缺少调查上下文")
    saved = deepcopy(saved)
    saved["messages"] = compact_context(saved["messages"])
    if context_size(saved["messages"]) > 95000:
        raise ValueError("检查点上下文接近上限，暂不能直接续跑；需要分范围新建调查")
    return saved
