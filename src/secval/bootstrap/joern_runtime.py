"""根据环境变量创建可选的 Joern 客户端。"""

import os
from pathlib import Path

from secval.infrastructure.joern import JoernClient


def create_optional_joern_client():
    url = os.getenv("SECVAL_JOERN_URL", "").strip()
    if not url:
        return None
    password = os.getenv("SECVAL_JOERN_PASSWORD", "")
    password_file = os.getenv("SECVAL_JOERN_PASSWORD_FILE", "").strip()
    if password_file:
        password = Path(password_file).read_text(encoding="utf-8").strip()
    client = JoernClient(url, os.getenv("SECVAL_JOERN_USER", "secval"), password,
                         int(os.getenv("SECVAL_JOERN_TIMEOUT_SECONDS", "600")))
    client.verify()
    return client
