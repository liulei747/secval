"""独立审计配置；密钥不进入repr。"""

import os
from dataclasses import dataclass, field


@dataclass(frozen=True)
class AuditSettings:
    api_url: str = field(repr=False)
    api_key: str = field(repr=False)
    model_name: str = "glm-5.3-flash"
    database_path: str = "data/audit/tasks.sqlite3"
    timeout_seconds: int = 120
    max_output_tokens: int = 8192
    thinking: str | None = None
    stream: bool = False

    def __post_init__(self):
        if self.thinking not in (None, "enabled", "disabled"):
            raise ValueError("审计思考模式必须为空、enabled或disabled")
        if type(self.max_output_tokens) is not int or not 256 <= self.max_output_tokens <= 32768:
            raise ValueError("审计模型输出上限必须为256到32768 token")
        if type(self.timeout_seconds) is not int or not 1 <= self.timeout_seconds <= 600:
            raise ValueError("审计模型单次请求超时必须为1到600秒")


def load_audit_settings():
    stream = os.getenv("SECVAL_AUDIT_STREAM", "false").strip().lower()
    if stream not in ("true", "false"):
        raise ValueError("审计流式接收开关必须为true或false")
    return AuditSettings(
        stream=stream == "true",
        api_url=os.getenv("SECVAL_AUDIT_API_URL", ""),
        api_key=os.getenv("SECVAL_AUDIT_API_KEY", ""),
        model_name=os.getenv("SECVAL_AUDIT_MODEL", "glm-5.3-flash"),
        database_path=os.getenv("SECVAL_AUDIT_DB", "data/audit/tasks.sqlite3"),
        timeout_seconds=int(os.getenv("SECVAL_AUDIT_TIMEOUT_SECONDS", "120")),
        max_output_tokens=int(os.getenv("SECVAL_AUDIT_MAX_OUTPUT_TOKENS", "8192")),
        thinking=os.getenv("SECVAL_AUDIT_THINKING", "").strip() or None,
    )
