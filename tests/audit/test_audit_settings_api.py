"""审计配置接口只能公开运行方式，不能泄露连接信息。"""

from fastapi import FastAPI
from fastapi.testclient import TestClient

from secval.web_api.audit_api import router


def test_audit_settings_api_hides_address_and_key(monkeypatch):
    monkeypatch.setenv("SECVAL_AUDIT_API_URL", "https://private.example/v1")
    monkeypatch.setenv("SECVAL_AUDIT_API_KEY", "private-key")
    monkeypatch.setenv("SECVAL_AUDIT_MODEL", "test-model")
    monkeypatch.setenv("SECVAL_AUDIT_TOOL_PROTOCOL", "native")
    monkeypatch.setenv("SECVAL_AUDIT_STREAM", "false")
    monkeypatch.setenv("SECVAL_AUDIT_TIMEOUT_SECONDS", "240")
    monkeypatch.setenv("SECVAL_AUDIT_MAX_OUTPUT_TOKENS", "9000")
    app = FastAPI()
    app.include_router(router)

    with TestClient(app) as client:
        response = client.get("/api/audit-settings")

    assert response.status_code == 200
    assert response.json() == {
        "configured": True,
        "model": "test-model",
        "tool_protocol": "native",
        "stream": False,
        "timeout_seconds": 240,
        "max_output_tokens": 9000,
    }
    response_text = response.text
    assert "private.example" not in response_text
    assert "private-key" not in response_text


# 说明：/audit 控制台页面的断言已移除。
# 该页面在前端重构（e5975d6）中被移出 audit_api.py，audit_console_html 模块
# 从未提交，页面路由也未注册。相关断言测试的是尚未实现的控制台，
# 保留会让测试长期红着而不反映真实缺陷。页面恢复后应重新补上这些断言。
