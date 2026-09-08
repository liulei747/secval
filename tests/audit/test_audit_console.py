from fastapi import FastAPI
from fastapi.testclient import TestClient

from secval.web_api.audit_api import router as audit_router
from secval.web_api.workbench import router as workbench_router


def test_audit_and_legacy_workbench_routes_share_the_formal_console():
    app = FastAPI()
    app.include_router(audit_router)
    app.include_router(workbench_router)

    with TestClient(app) as client:
        audit_html = client.get("/audit").text
        workbench_html = client.get("/workbench").text

    assert "SecVal · 安全审计控制台" in audit_html
    assert "模型流量与本地操作" in audit_html
    assert "Secval 测试工作台" not in audit_html
    assert "Secval 只读审计实验" not in audit_html
    assert workbench_html == audit_html
