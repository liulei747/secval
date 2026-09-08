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


def compact_context(messages, *, threshold=30000, keep_recent=4):
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
    if context_size(result) > threshold:
        _compact_recorded_action_pairs(result, keep_recent)
    if context_size(result) > threshold:
        _compact_read_pairs(result, keep_recent)
    return result


def _compact_recorded_action_pairs(messages, keep_recent):
    """把旧写入动作替换为小回执；完整结构仍由任务台账保存。"""

    record_tools = {
        "record_boundary", "record_investigation", "review_investigation",
        "record_finding_detail", "record_file_review", "record_threat_model",
    }
    for message in messages[:max(0, len(messages) - keep_recent)]:
        if message.get("role") != "assistant":
            continue
        try:
            action = json.loads(message.get("content", ""))
        except (TypeError, ValueError):
            continue
        if not isinstance(action, dict) or action.get("tool") not in record_tools:
            continue
        arguments = action.get("arguments") if isinstance(action.get("arguments"), dict) else {}
        receipt = {"recorded_action": action["tool"]}
        for key in ("investigation_id", "file_id", "outcome", "title", "ruleId"):
            if isinstance(arguments.get(key), str):
                receipt[key] = arguments[key]
        message["content"] = json.dumps(receipt, ensure_ascii=False)


def _compact_read_pairs(messages, keep_recent):
    """旧读取只保留可重读定位，避免每轮重发源码和搜索结果。"""

    end = max(0, len(messages) - keep_recent)
    for index in range(min(end, len(messages) - 1)):
        assistant, reply = messages[index], messages[index + 1]
        if assistant.get("role") != "assistant" or reply.get("role") != "user":
            continue
        try:
            action = json.loads(assistant.get("content", ""))
        except (TypeError, ValueError):
            continue
        if not isinstance(action, dict) or action.get("tool") not in {
            "read_file", "read_chunk", "list_files", "list_chunks", "search_text",
            "search_source", "hybrid_search", "find_symbol", "find_entry_points",
            "find_code_relations", "find_code_callers", "find_code_callees",
            "find_code_type_relations", "find_dispatch_targets", "find_code_calls",
            "find_data_paths",
        }:
            continue
        prefix = next((value for value in ("工具数据：", "不可信工具数据：")
                       if str(reply.get("content", "")).startswith(value)), None)
        if prefix is None:
            continue
        try:
            payload = json.loads(reply["content"][len(prefix):])
        except (TypeError, ValueError):
            continue
        rows = payload.get("rows", []) if isinstance(payload, dict) else []
        locations = []
        for row in rows[:30] if isinstance(rows, list) else []:
            if not isinstance(row, dict):
                continue
            item = {key: row[key] for key in (
                "evidence_id", "chunk_id", "relative_path", "path", "symbol_name",
                "start_line", "end_line", "content_sha256",
            ) if key in row}
            if item:
                locations.append(item)
        arguments = action.get("arguments") if isinstance(action.get("arguments"), dict) else {}
        assistant["content"] = json.dumps({"completed_read": action["tool"],
                                             "arguments": arguments}, ensure_ascii=False)
        reply["content"] = prefix + json.dumps({
            "result_count": len(rows) if isinstance(rows, list) else None,
            "locations": locations,
            "context_note": "完整结果已保存；需要源码正文时按定位重新读取固定快照。",
        }, ensure_ascii=False)


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
