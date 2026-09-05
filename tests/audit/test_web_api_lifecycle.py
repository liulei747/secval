"""离线走真实Web路由与业务服务，验证取消、检查点续跑和导出。"""

from concurrent.futures import ThreadPoolExecutor
from threading import Event
from unittest.mock import MagicMock

from fastapi import FastAPI
from fastapi.testclient import TestClient

from secval.infrastructure.audit.sqlite_audit_store import AuditStore
from secval.services.audit_service import AuditService
from secval.web_api.audit_api import router


def test_cancel_resume_and_export_through_http(tmp_path):
    started = Event()
    release = Event()
    first_model = MagicMock()

    def waiting_response(messages):
        started.set()
        assert release.wait(timeout=5)
        return {"questions": [], "unknowns": ["取消后的响应不可作为结果"]}

    first_model.next_action.side_effect = waiting_response
    resumed_model = MagicMock()
    resumed_model.next_action.side_effect = [
        {"questions": [], "unknowns": ["离线测试不作安全判断"]},
        {"report": {"summary": "离线部分报告", "hypotheses": [], "unknowns": ["未完成安全调查"]}},
    ]
    partial_model = MagicMock()
    partial_model.next_action.return_value = {"report": {"summary": "继续部分报告", "hypotheses": [],
                                                          "unknowns": ["仍需进一步调查"]}}
    models = iter([first_model, resumed_model, partial_model])

    def make_tools(repo, snapshot):
        tools = MagicMock()

        def call(name, arguments):
            if name == "list_chunks":
                return {"total": 1, "rows": []}
            if name == "scope_info":
                return {"repository_id": repo, "snapshot_id": snapshot, "source_snapshot_id": "source",
                        "index_run_id": "run", "_inventory": [{"path": "Test.java", "digest": "test",
                                                                  "status": "captured"}]}
            raise AssertionError("不应访问其他工具")

        tools.call.side_effect = call
        return tools

    service = AuditService(AuditStore(tmp_path / "tasks.sqlite3"), ThreadPoolExecutor(max_workers=1),
                           lambda: next(models), make_tools)
    app = FastAPI()
    app.state.audit_service = service
    app.include_router(router)
    try:
        with TestClient(app) as client:
            request = {"objective": "测试取消和续跑", "repository_id": "repo", "snapshot_id": "snap",
                       "max_steps": 9, "allow_remote_code": True, "parallel_agents": 1}
            assert client.post("/api/audits", json={**request, "allow_remote_code": False}).status_code == 400
            response = client.post("/api/audits", json=request)
            assert response.status_code == 202
            parent_id = response.json()["id"]
            assert started.wait(timeout=5)
            assert client.post(f"/api/audits/{parent_id}/cancel").json()["status"] == "cancelled"
            release.set()
            service.future.result(timeout=5)
            assert service.get(parent_id)["status"] == "cancelled"
            response = client.post(f"/api/audits/{parent_id}/resume",
                                   json={"max_steps": 9, "allow_remote_code": True})
            assert response.status_code == 202
            child_id = response.json()["id"]
            assert child_id != parent_id
            service.future.result(timeout=5)
            response = client.get(f"/api/audits/{child_id}/report")
            assert response.status_code == 200
            assert response.headers["cache-control"] == "no-store"
            assert "attachment" in response.headers["content-disposition"]
            assert response.json()["status"] == "needs_review"
            assert response.json()["coverage"]["complete"] is False
            assert service.get(child_id)["parent_task_id"] == parent_id
            assert service.get(parent_id)["status"] == "cancelled"
            original_report = response.json()
            continuation = client.post(f"/api/audits/{child_id}/resume",
                                       json={"max_steps": 9, "allow_remote_code": True})
            assert continuation.status_code == 202
            service.future.result(timeout=5)
            next_id = continuation.json()["id"]
            assert service.get(next_id)["parent_report_submitted"] is True
            assert service.get(next_id).get("independent_reviews", []) == []
            assert client.get(f"/api/audits/{child_id}/report").json() == original_report
            assert client.get("/api/audits/missing/report").status_code == 404
    finally:
        release.set()
        service.close()
