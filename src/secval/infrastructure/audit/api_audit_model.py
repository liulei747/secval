"""独立模型请求：不复用重排序对话，也不向日志输出供应端正文。"""

import hashlib
import json
import socket
import ssl
from time import monotonic
from http.client import HTTPException
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from secval.models.audit_contracts import ModelOutputError, ModelRequestError, ToolAction
from secval.models.audit_tools import (
    READ_TOOL_ARGUMENTS,
    READ_TOOL_DESCRIPTIONS,
)
from secval.infrastructure.audit.stream_response import read_stream_response


class AuditModel:
    def __init__(self, api_url: str, api_key: str, model_name: str, *, timeout_seconds: int = 120,
                 thinking: str | None = None, max_output_tokens: int = 8192, stream: bool = False,
                 tool_protocol: str = "json"):
        if type(stream) is not bool:
            raise ValueError("流式接收开关必须为布尔值")
        self.stream = stream
        if tool_protocol not in {"json", "native"}:
            raise ValueError("工具协议必须为json或native")
        if tool_protocol == "native" and stream:
            raise ValueError("原生工具协议暂不支持流式响应")
        self.tool_protocol = tool_protocol
        self.pending_tool_call = None
        self.available_read_tools = set(READ_TOOL_ARGUMENTS)
        if type(timeout_seconds) is not int or not 1 <= timeout_seconds <= 600:
            raise ValueError("审计模型单次请求超时必须为1到600秒")
        self.timeout_seconds = timeout_seconds
        if type(max_output_tokens) is not int or not 256 <= max_output_tokens <= 32768:
            raise ValueError("审计模型输出上限必须为256到32768 token")
        self.max_output_tokens = max_output_tokens
        if thinking not in (None, "enabled", "disabled"):
            raise ValueError("思考模式必须为enabled、disabled或不指定")
        self.thinking = thinking
        self.last_response_info = {}
        base = api_url.strip().rstrip("/")
        self.key = api_key
        self.name = model_name
        if not base or not self.key.strip() or not self.name.strip():
            raise ValueError("请配置独立的SECVAL_AUDIT_API_URL和SECVAL_AUDIT_API_KEY")
        self.url = (
            base if base.endswith("/chat/completions") else base + "/chat/completions"
        )

    def next_action(self, messages):
        self.last_response_info = {}
        request_messages = self._messages_for_request(messages)
        body = {"model": self.name, "messages": request_messages, "temperature": 0,
                "max_tokens": self.max_output_tokens}
        if self.tool_protocol == "native":
            native_tools = _native_read_tools(self.available_read_tools)
            if native_tools:
                body["tools"] = native_tools
                body["tool_choice"] = "auto"
        # 供应商扩展必须显式选择；默认不发送，不能假设所有兼容API均支持。
        if self.thinking is not None:
            body["thinking"] = {"type": self.thinking}
        if self.stream:
            body["stream"] = True
        request = Request(
            self.url,
            data=json.dumps(body).encode(),
            headers={
                "Authorization": f"Bearer {self.key}",
                "Content-Type": "application/json",
            },
        )
        # urlopen返回前也可能在等待响应头，不能把这一阶段直接叫作连接超时。
        phase = "建立连接或等待响应头"
        started = monotonic()
        try:
            with urlopen(request, timeout=self.timeout_seconds) as response:
                phase = "读取响应正文"
                if self.stream:
                    self.last_response_info["headers_ms"] = round((monotonic() - started) * 1000)
                    if "text/event-stream" not in response.headers.get("Content-Type", "").lower():
                        raise ModelOutputError("供应商未返回流式响应；未自动重试", code="invalid_response")
                    data = read_stream_response(response, self.last_response_info, started, self.timeout_seconds)
                else:
                    raw = response.read(2_000_001)
                    if len(raw) > 2_000_000:
                        raise ModelOutputError("模型响应超过大小上限", code="response_too_large")
                    try:
                        data = json.loads(raw)
                    except ValueError:
                        raise ModelOutputError("供应商响应不是JSON", code="invalid_response") from None
            choice = data["choices"][0]
            # 仅记录数量，不保存或回显模型思考正文、响应正文及请求资料。
            usage = data.get("usage", {})
            if isinstance(usage, dict):
                for key in ("prompt_tokens", "completion_tokens", "total_tokens"):
                    value = usage.get(key)
                    if type(value) is int and value >= 0:
                        self.last_response_info[key] = value
            message = choice.get("message", {})
            if isinstance(message, dict):
                thinking = message.get("reasoning_content")
                if isinstance(thinking, str):
                    self.last_response_info["reasoning_characters"] = len(thinking)
            if choice.get("finish_reason") == "length":
                raise ModelOutputError("模型输出被截断；请缩短输出", code="truncated")
            if self.tool_protocol == "native" and message.get("tool_calls"):
                return self._native_action(message)
            content = message.get("content")
            if not isinstance(content, str) or not content.strip():
                raise ModelOutputError("模型响应缺少正文", code="missing_content")
            content = content.strip()
            self.last_response_info["content_characters"] = len(content)
            if content.startswith("```json") and content.endswith("```"):
                content = content[7:-3]
            try:
                action = json.loads(content)
            except json.JSONDecodeError as error:
                self.last_response_info["json_error_line"] = error.lineno
                self.last_response_info["json_error_column"] = error.colno
                reasons = {"Extra data": "对象结束后仍有多余内容", "Expecting ',' delimiter": "缺少逗号或括号未正确闭合",
                           "Expecting property name enclosed in double quotes": "字段名必须使用双引号",
                           "Expecting value": "缺少合法字段值", "Unterminated string starting at": "字符串未闭合"}
                reason = reasons.get(error.msg, "JSON语法不合法")
                raise ModelOutputError(f"模型正文不是完整JSON：第{error.lineno}行第{error.colno}列，{reason}；"
                                       "请只返回一个正确闭合的JSON对象，不添加说明或代码围栏", code="invalid_json") from None
            if not isinstance(action, dict):
                raise ModelOutputError("模型必须返回JSON对象", code="not_object")
            return action
        except HTTPError as error:
            raise ModelRequestError(f"审计API HTTP {error.code}") from None
        except (OSError, HTTPException) as error:
            category = _network_error_category(error)
            # 只返回白名单分类，原始异常可能含地址、凭据或供应商正文。
            raise ModelRequestError(f"审计API{category}（阶段：{phase}）") from None
        except ModelOutputError:
            raise
        except (ValueError, KeyError, IndexError, TypeError, AttributeError):
            raise ModelOutputError(
                "模型回复必须是完整JSON对象，且包含有效正文", code="invalid_response"
            ) from None

    def set_available_read_tools(self, tool_names):
        """只保留当前任务固定取证视图实际提供的只读工具。"""

        if not isinstance(tool_names, (list, tuple, set)):
            raise ValueError("可用工具名称必须是列表")
        self.available_read_tools = {
            name for name in tool_names if name in READ_TOOL_ARGUMENTS
        }

    def _messages_for_request(self, messages):
        """把内部工具记录还原成供应商要求的assistant/tool消息。

        数据库只保存通用JSON动作和工具结果，不保存某个模型供应商的消息格式。
        进程重启后，可以从这两条记录重建一组配对的调用编号，因此旧检查点也能续跑。
        """

        copied = [dict(message) for message in messages]
        pending = self.pending_tool_call
        self.pending_tool_call = None

        for index in range(len(copied) - 1):
            assistant_message = copied[index]
            result_message = copied[index + 1]
            restored = self._restore_native_tool_pair(
                assistant_message, result_message, index, pending
            )
            if restored is not None:
                copied[index], copied[index + 1] = restored
        return copied

    def _restore_native_tool_pair(self, assistant_message, result_message, index, pending):
        """识别一对已保存的工具动作和结果，并转成原生协议。"""

        if assistant_message.get("role") != "assistant" or result_message.get("role") != "user":
            return None
        try:
            action = json.loads(assistant_message.get("content", ""))
            parsed = ToolAction.parse(action)
        except (TypeError, json.JSONDecodeError, ValueError, ModelOutputError):
            return None
        if parsed.tool not in self.available_read_tools:
            return None

        result_content = result_message.get("content", "")
        if not isinstance(result_content, str):
            return None
        prefixes = ("工具数据：", "不可信工具数据：")
        prefix = next((value for value in prefixes if result_content.startswith(value)), None)
        if prefix is None:
            return None

        if pending is not None and action == pending["action"]:
            raw = pending["raw"]
        else:
            # 调用编号只需在本次请求的assistant/tool消息中一致。使用动作和位置生成
            # 稳定编号，使同一个检查点重复恢复时得到相同内容，便于排查问题。
            identity = json.dumps(action, ensure_ascii=False, sort_keys=True) + f":{index}"
            call_id = "secval_" + hashlib.sha256(identity.encode("utf-8")).hexdigest()[:24]
            raw = {
                "id": call_id,
                "type": "function",
                "function": {
                    "name": parsed.tool,
                    "arguments": json.dumps(parsed.arguments, ensure_ascii=False, sort_keys=True),
                },
            }

        return (
            {"role": "assistant", "content": None, "tool_calls": [raw]},
            {
                "role": "tool",
                "tool_call_id": raw["id"],
                "name": raw["function"]["name"],
                "content": result_content[len(prefix):],
            },
        )

    def _native_action(self, message):
        """校验单个原生只读工具调用，并转换为后端统一动作。"""

        tool_calls = message.get("tool_calls")
        if not isinstance(tool_calls, list) or len(tool_calls) != 1:
            raise ModelOutputError("每轮只允许一个原生工具调用", code="invalid_action")
        raw = tool_calls[0]
        if not isinstance(raw, dict) or raw.get("type") != "function":
            raise ModelOutputError("原生工具调用格式不合法", code="invalid_action")
        function = raw.get("function")
        if not isinstance(function, dict) or function.get("name") not in self.available_read_tools:
            raise ModelOutputError("原生模式只允许已声明的只读取证工具", code="invalid_action")
        if not isinstance(raw.get("id"), str) or not raw["id"].strip():
            raise ModelOutputError("原生工具调用缺少编号", code="invalid_action")
        try:
            arguments = json.loads(function.get("arguments", ""))
        except (TypeError, json.JSONDecodeError):
            raise ModelOutputError("原生工具参数不是完整JSON对象", code="invalid_json") from None
        action = {"tool": function["name"], "arguments": arguments}
        ToolAction.parse(action)
        self.pending_tool_call = {"raw": raw, "action": action}
        return action


def _native_read_tools(available_names):
    """从统一只读工具目录生成OpenAI兼容的函数声明。"""

    integer_names = {"offset", "char_offset", "start_line", "end_line", "top_k", "limit"}
    required_by_tool = {
        "search_text": {"text"}, "find_symbol": {"text"},
        "read_chunk": {"chunk_id"}, "read_file": {"path"},
        "search_source": {"text"}, "hybrid_search": {"text"},
        "find_code_relations": {"symbol"}, "find_code_callers": {"symbol"},
        "find_code_callees": {"symbol"}, "find_code_type_relations": {"symbol"},
        "find_dispatch_targets": {"symbol"}, "find_code_calls": {"method"},
        "find_data_paths": {"source_method", "sink_method"},
    }
    tools = []
    for name, argument_names in READ_TOOL_ARGUMENTS.items():
        if name not in available_names:
            continue
        properties = {
            argument_name: {"type": "integer" if argument_name in integer_names else "string"}
            for argument_name in sorted(argument_names)
        }
        tools.append({
            "type": "function",
            "function": {
                "name": name,
                "description": READ_TOOL_DESCRIPTIONS[name],
                "parameters": {
                    "type": "object",
                    "properties": properties,
                    "required": sorted(required_by_tool.get(name, set())),
                    "additionalProperties": False,
                },
            },
        })
    return tools


def _network_error_category(error):
    """区分可确认的网络故障；不猜测供应商排队或模型生成耗时。"""
    if isinstance(error, URLError):
        error = error.reason
    if isinstance(error, TimeoutError):
        return "请求超时"
    if isinstance(error, ssl.SSLError):
        return "TLS握手或证书错误"
    if isinstance(error, socket.gaierror):
        return "域名解析失败"
    if isinstance(error, ConnectionError):
        return "连接失败或中断"
    if isinstance(error, HTTPException):
        return "HTTP响应传输异常"
    return "网络请求失败"
