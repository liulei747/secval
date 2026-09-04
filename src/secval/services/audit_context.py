"""确定性缩减旧工具消息中的源码正文；不总结、改写或删除审计判断。"""

import json
from copy import deepcopy

PREFIXES = ("工具数据：", "独立基线问题（非结论）与已读证据：")


def context_size(messages):
    return sum(len(message["content"]) for message in messages)


def compact_context(messages, *, threshold=80000, keep_recent=4):
    if context_size(messages) <= threshold:
        return messages
    result = deepcopy(messages)
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
