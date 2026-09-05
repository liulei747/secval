"""创建可选的 Neo4j 代码关系存储。"""

import os
from pathlib import Path

from neo4j import GraphDatabase

from secval.infrastructure.neo4j import CodeGraphStore


def create_optional_code_graph_store():
    """未配置 Neo4j 时返回 None，避免本地单元测试被外部服务阻塞。"""

    uri = os.getenv("SECVAL_NEO4J_URI", "").strip()
    if not uri:
        return None

    user = os.getenv("SECVAL_NEO4J_USER", "neo4j").strip()
    password = os.getenv("SECVAL_NEO4J_PASSWORD", "")
    password_file = os.getenv("SECVAL_NEO4J_PASSWORD_FILE", "").strip()
    if password_file:
        password = Path(password_file).read_text(encoding="utf-8").strip()
        # Docker secret 使用“用户名/密码”格式时，只取斜杠后的密码。
        if "/" in password:
            file_user, password = password.split("/", 1)
            if not user:
                user = file_user
    if not user or not password:
        raise ValueError("已启用 Neo4j，但用户名或密码为空")

    store = CodeGraphStore(GraphDatabase.driver(uri, auth=(user, password)))
    store.verify()
    store.create_constraints()
    return store
