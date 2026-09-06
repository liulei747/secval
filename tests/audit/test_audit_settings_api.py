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


def test_audit_page_displays_runtime_settings():
    app = FastAPI()
    app.include_router(router)

    with TestClient(app) as client:
        page = client.get("/audit")

    assert page.status_code == 200
    assert "/api/audit-settings" in page.text
    assert "工具协议" in page.text


def test_audit_page_exposes_resume_budget_and_completion_state():
    """续跑预算和报告收口必须能在页面上直接看到，不能只藏在完整JSON里。"""

    app = FastAPI()
    app.include_router(router)

    with TestClient(app) as client:
        page = client.get("/audit")

    assert page.status_code == 200
    # 续跑复用同一组预算输入；保证页面请求体包含这些字段。
    assert "max_steps:Number(el('steps').value)" in page.text
    assert "max_seconds:Number(el('seconds').value)" in page.text
    assert "从检查点续跑" in page.text
    # 报告完成度有独立展示区域，并请求导出接口读取completion状态。
    assert "报告收口状态" in page.text
    assert "completion.pendingReasons" not in page.text or "未收口原因" in page.text
    assert "/report" in page.text
