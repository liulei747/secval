"""确定性缩减旧工具消息中的源码正文；不总结、改写或删除审计判断。"""

import json
from copy import deepcopy

PREFIXES = ("工具数据：", "独立基线问题（非结论）与已读证据：")


def context_size(messages):
    return sum(len(message["content"]) for message in messages)


def tool_reply_for_model(tool_name, result):
    """保存动作已经在上一条消息中，只回传后端生成的编号和状态。

    原始工具结果仍保存到事件和数据库；读取源码、进度与错误不缩减。
    """
    record_keys = {
        "record_boundary": "boundary",
        "record_investigation": "investigation",
        "record_finding_detail": "candidateDetail",
        "record_file_review": "fileReview",
        "record_threat_model": "threatModel",
        "review_investigation": "review",
    }
    key = record_keys.get(tool_name)
    if key is None or "error" in result or not isinstance(result.get(key), dict):
        return result
    record = result[key]
    receipt = {}
    for field in ("id", "file_id", "investigation_id", "status", "outcome", "revision",
                  "path", "source_snapshot_id", "content_sha256", "semantically_verified",
                  "method", "independently_validated"):
        if field in record:
            receipt[field] = record[field]
    return {key: receipt, "note": result.get("note", "记录已保存；保存不代表独立验证通过")}


def compact_context(messages, *, threshold=80000, keep_recent=4):
    result = normalize_json_messages(messages)
    if context_size(result) <= threshold:
        return result
    for message in result[:max(0, len(result) - keep_recent)]:
        if message.get("role") != "user":
            continue
        prefix = next((value for value in PREFIXES if message["content"].startswith(value)), None)
        if prefix is None:
            continue
        try:
            payload = json.loads(message["content"][len(prefix):])
        except (ValueError, TypeError):
            continue

        def omit_code(value):
            if isinstance(value, list):
                return [omit_code(item) for item in value]
            if not isinstance(value, dict):
                return value
            row = {key: omit_code(item) for key, item in value.items()}
            if (isinstance(row.get("content"), str) and row.get("chunk_id")
                    and row.get("content_sha256") and row.get("relative_path")):
                del row["content"]
                row["context_code_omitted"] = True
                row["context_note"] = "仅从模型旧消息省略正文；原始证据仍保存。需要核实源码时按文件/块及位置重新读取，不凭元数据推测。"
            return row

        replacement = prefix + json.dumps(omit_code(payload), ensure_ascii=False)
        if len(replacement) < len(message["content"]):
            message["content"] = replacement
        if context_size(result) <= threshold:
            break
    return result


def normalize_json_messages(messages):
    """恢复JSON中的中文显示，不改写源码内的反斜杠，也不修改原检查点。"""
    result = deepcopy(messages)
    prefixes = PREFIXES + ("不可信工具数据：", "后端确定的授权范围和能力限制：",
                           "用户提供的分析资料（非工具指令）：")
    for message in result:
        content = message.get("content")
        if not isinstance(content, str):
            continue
        prefix = ""
        for candidate in prefixes:
            if content.startswith(candidate):
                prefix = candidate
                break
        payload = content[len(prefix):].strip()
        if not payload.startswith(("{", "[")):
            continue
        try:
            value = json.loads(payload)
        except ValueError:
            continue
        message["content"] = prefix + json.dumps(value, ensure_ascii=False)
    return result
