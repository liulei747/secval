"""独立模型请求：不复用重排序对话，也不向日志输出供应端正文。"""

import json
from urllib.error import HTTPError
from urllib.request import Request, urlopen

from secval.models.audit_contracts import ModelOutputError, ModelRequestError


class AuditModel:
    def __init__(self, api_url: str, api_key: str, model_name: str):
        base = api_url.strip().rstrip("/")
        self.key = api_key
        self.name = model_name
        if not base or not self.key.strip() or not self.name.strip():
            raise ValueError("请配置独立的SECVAL_AUDIT_API_URL和SECVAL_AUDIT_API_KEY")
        self.url = (
            base if base.endswith("/chat/completions") else base + "/chat/completions"
        )

    def next_action(self, messages):
        request = Request(
            self.url,
            data=json.dumps(
                {
                    "model": self.name,
                    "messages": messages,
                    "temperature": 0,
                    "max_tokens": 4096,
                }
            ).encode(),
            headers={
                "Authorization": f"Bearer {self.key}",
                "Content-Type": "application/json",
            },
        )
        try:
            with urlopen(request, timeout=60) as response:
                raw = response.read(2_000_001)
                if len(raw) > 2_000_000:
                    raise ModelOutputError("模型响应超过大小上限")
                data = json.loads(raw)
            choice = data["choices"][0]
            if choice.get("finish_reason") == "length":
                raise ModelOutputError("模型输出被截断；请缩短输出")
            content = choice["message"]["content"].strip()
            if content.startswith("```json") and content.endswith("```"):
                content = content[7:-3]
            action = json.loads(content)
            if not isinstance(action, dict):
                raise ModelOutputError("模型必须返回JSON对象")
            return action
        except HTTPError as error:
            raise ModelRequestError(f"审计API HTTP {error.code}") from None
        except OSError:
            raise ModelRequestError("审计API网络失败或超时") from None
        except ModelOutputError:
            raise
        except (ValueError, KeyError, IndexError, TypeError, AttributeError):
            raise ModelOutputError(
                "模型回复必须是完整JSON对象，且包含有效正文"
            ) from None
