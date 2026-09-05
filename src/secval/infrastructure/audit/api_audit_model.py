"""独立模型请求：不复用重排序对话，也不向日志输出供应端正文。"""

import json
import socket
import ssl
from time import monotonic
from http.client import HTTPException
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from secval.models.audit_contracts import ModelOutputError, ModelRequestError
from secval.infrastructure.audit.stream_response import read_stream_response


class AuditModel:
    def __init__(self, api_url: str, api_key: str, model_name: str, *, timeout_seconds: int = 120,
                 thinking: str | None = None, max_output_tokens: int = 8192, stream: bool = False):
        if type(stream) is not bool:
            raise ValueError("流式接收开关必须为布尔值")
        self.stream = stream
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
        body = {"model": self.name, "messages": messages, "temperature": 0,
                "max_tokens": self.max_output_tokens}
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
            content = choice["message"].get("content")
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
