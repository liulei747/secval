"""独立审计配置；密钥不进入repr。"""

import os
from dataclasses import dataclass, field


@dataclass(frozen=True)
class AuditSettings:
    api_url: str = field(repr=False)
    api_key: str = field(repr=False)
    model_name: str = "glm-5.3-flash"
    database_path: str = "data/audit/tasks.sqlite3"


def load_audit_settings():
    return AuditSettings(
        api_url=os.getenv("SECVAL_AUDIT_API_URL", ""),
        api_key=os.getenv("SECVAL_AUDIT_API_KEY", ""),
        model_name=os.getenv("SECVAL_AUDIT_MODEL", "glm-5.3-flash"),
        database_path=os.getenv("SECVAL_AUDIT_DB", "data/audit/tasks.sqlite3"),
    )
