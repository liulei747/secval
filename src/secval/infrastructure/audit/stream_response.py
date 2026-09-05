"""接收流式模型结果；只拼接最终正文，不保存思考正文。"""

import json
from time import monotonic

from secval.models.audit_contracts import ModelOutputError


def read_stream_response(response, info, started, timeout_seconds):
    content_parts = []
    event_lines = []
    received_bytes = 0
    finish_reason = None
    reasoning_characters = 0
    usage = {}

    while True:
        # 防止不断发送心跳的响应无限延长；阻塞读取另受网络超时保护。
        if monotonic() - started >= timeout_seconds:
            raise TimeoutError()
        line = response.readline(2_000_001 - received_bytes)
        if monotonic() - started >= timeout_seconds:
            raise TimeoutError()
        if not line:
            raise ModelOutputError("模型流提前结束，未执行不完整动作", code="invalid_response")
        received_bytes += len(line)
        if received_bytes > 2_000_000:
            raise ModelOutputError("模型响应超过大小上限", code="response_too_large")
        if "first_data_ms" not in info:
            info["first_data_ms"] = round((monotonic() - started) * 1000)
        line = line.decode("utf-8").rstrip("\r\n")
        if line.startswith("data:"):
            event_lines.append(line[5:].lstrip(" "))
            continue
        if line or not event_lines:
            continue
        value = "\n".join(event_lines)
        event_lines = []
        if value == "[DONE]":
            if finish_reason not in ("stop", "length"):
                raise ModelOutputError("模型流缺少正常结束标记", code="invalid_response")
            info["reasoning_characters"] = reasoning_characters
            return {"choices": [{"finish_reason": finish_reason,
                                  "message": {"content": "".join(content_parts)}}], "usage": usage}
        event = json.loads(value)
        if "error" in event:
            raise ModelOutputError("模型流返回错误，未执行动作", code="invalid_response")
        if isinstance(event.get("usage"), dict):
            usage = event["usage"]
        for choice in event.get("choices", []):
            if choice.get("index", 0) != 0:
                raise ModelOutputError("模型流返回多个候选", code="invalid_response")
            delta = choice.get("delta", {})
            if delta.get("tool_calls") or delta.get("function_call"):
                raise ModelOutputError("模型流未按JSON动作约定返回", code="invalid_response")
            content = delta.get("content")
            if content is not None:
                if not isinstance(content, str):
                    raise ModelOutputError("模型流正文格式错误", code="invalid_response")
                content_parts.append(content)
            thinking = delta.get("reasoning_content")
            if isinstance(thinking, str):
                reasoning_characters += len(thinking)
            if choice.get("finish_reason") is not None:
                finish_reason = choice["finish_reason"]
