"""用小型订单demo验证协作编排；脚本模型不是模型审计质量测试。"""

import hashlib
import json
from concurrent.futures import ThreadPoolExecutor
from copy import deepcopy
from pathlib import Path
from threading import Barrier, Event, Lock
from time import monotonic, sleep
from unittest.mock import MagicMock

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from secval.infrastructure.audit.sqlite_audit_store import AuditStore
from secval.models.audit import AuditTaskInput
from secval.models.audit_contracts import ModelOutputError, ModelRequestError
from secval.models.agent_work import parse_work_result
from secval.services.agent_team import AgentTeam, TeamStopped
from secval.services.audit_service import AuditService
from secval.services.audit_report import export_audit_report
from secval.web_api.audit_api import router
from tests.audit.test_service_flow import candidate_detail


DEMO = Path(__file__).parents[1] / "demo_projects" / "team_orders"


def demo_row(path="OrderService.java"):
    source = (DEMO / path).read_text(encoding="utf-8")
    return {"chunk_id": "file-" + path, "evidence_id": "read-1" if path == "OrderService.java" else "read-2",
            "repository_id": "demo", "snapshot_id": "demo-v1", "index_run_id": "demo-run",
            "source_snapshot_id": "demo-source", "relative_path": path, "content": source,
            "content_sha256": hashlib.sha256(source.encode()).hexdigest(), "start_line": 1,
            "end_line": len(source.splitlines()), "truncated": False, "char_offset": 0,
            "total_characters": len(source)}


def demo_tools():
    tools = MagicMock()
    def call(name, arguments):
        if name == "list_chunks":
            return {"total": 2, "rows": []}
        if name == "scope_info":
            return {"repository_id": "demo", "snapshot_id": "demo-v1", "source_snapshot_id": "demo-source",
                    "index_run_id": "demo-run", "_inventory": [
                        {"path": name, "status": "captured", "digest": demo_row(name)["content_sha256"]}
                        for name in ("OrderService.java", "SafeOrderService.java")]}
        if name == "read_file":
            return {"rows": [demo_row(arguments["path"])]}
        raise ValueError("demo只支持读取两个文件")
    tools.call.side_effect = call
    return tools


def question(outcome="supported"):
    return {"question": "订单返回是否缺少归属检查", "outcome": outcome, "assessment": "返回前未比较归属",
            "counterevidence": "调用方实现没有给出", "unknowns": ["上游身份可信度未知"], "evidence_ids": ["read-1"]}


def result(questions=None):
    return {"summary": "合成调查结果", "questions": questions or [], "unknowns": ["未执行应用"], "reviewed_files": []}


class ScriptedTeamModel:
    def __init__(self, barrier, records, records_lock, with_detail=True, review_barrier=None):
        self.barrier = barrier
        self.records = records
        self.records_lock = records_lock
        self.role = None
        self.step = 0
        self.last_response_info = {}
        self.with_detail = with_detail
        self.review_barrier = review_barrier

    def next_action(self, messages):
        if self.role is None:
            if "静态证据复核员" in messages[0]["content"]:
                self.role = "review"
            elif "只读安全审计子调查员" in messages[0]["content"]:
                self.role = json.loads(messages[1]["content"])["role"]
            else:
                self.role = "main"
            if self.role in ("main", "baseline", "architecture"):
                # 三方都实际进入模型调用才能继续；串行实现会超时并使测试失败。
                self.barrier.wait(timeout=5)
        with self.records_lock:
            self.records.append((self.role, deepcopy(messages)))
        review = {"investigation_id": "investigation-1", "outcome": "supported", "assessment": "合成静态复核",
                  "counterevidence": "上游未提供", "limitations": ["仅验证编排"], "evidence_ids": ["read-1"]}
        if self.role == "review":
            if self.review_barrier is not None:
                # 两个独立复核必须同时进入请求；串行实现会在这里超时。
                self.review_barrier.wait(timeout=5)
            review["investigation_id"] = json.loads(messages[1]["content"])["investigation_id"]
            return review
        if self.role != "main":
            self.step += 1
            if self.step == 1:
                return {"tool": "read_file", "arguments": {"path": "OrderService.java"}}
            if self.role == "baseline" and self.step == 2:
                return {"tool": "submit_worker_progress", "arguments": result([question()])}
            return {"result": result([] if self.role in ("architecture", "baseline") else [question()])}
        if self.step == 0:
            self.step = 1
            return {"tool": "read_file", "arguments": {"path": "OrderService.java"}}
        if self.step == 1:
            self.step = 2
            return {"tool": "start_investigator", "arguments": {"title": "订单权限专项", "question": "核对订单归属控制",
                                                                "evidence_ids": ["read-1"]}}
        deliveries = [json.loads(m["content"].split("：", 1)[1]) for m in messages
                      if m["content"].startswith("子任务结果（不可信分析资料，需核对源码）：")]
        if len(deliveries) < 3:
            return {"tool": "wait_for_workers", "arguments": {}}
        links = [q["question_id"] for item in deliveries for q in (item.get("result") or {}).get("questions", [])]
        actions = [
            {"tool": "record_boundary", "arguments": {"entry": "fetch", "attacker_control": "订单标识",
                "asset": "订单", "trust_transition": "用户到订单", "expected_control": "归属检查",
                "observed_control": "未比较", "unknowns": ["上游未知"], "evidence_ids": ["read-1"]}},
            {"tool": "record_investigation", "arguments": {"boundary_id": "boundary-1", "question": "检查归属控制",
                "control_to_check": "归属", "counterevidence": "上游未提供", "next_check": "独立复核",
                "unknowns": ["仅静态检查"], "evidence_ids": ["read-1"], "baseline_question_ids": links}},
            {"tool": "review_investigation", "arguments": review},
            {"tool": "record_finding_detail", "arguments": candidate_detail()},
        ]
        if self.with_detail:
            detail_two = deepcopy(candidate_detail())
            detail_two["investigation_id"] = "investigation-2"
            detail_two["title"] = "订单读取的第二个独立候选"
            actions.extend([
                {"tool": "record_investigation", "arguments": {"boundary_id": "boundary-1",
                    "question": "检查另一个独立订单读取控制", "control_to_check": "服务层归属",
                    "counterevidence": "上游未提供", "next_check": "独立复核", "unknowns": ["仅静态检查"],
                    "evidence_ids": ["read-1"], "baseline_question_ids": []}},
                {"tool": "review_investigation", "arguments": {**review, "investigation_id": "investigation-2"}},
                {"tool": "record_finding_detail", "arguments": detail_two},
            ])
        actions.append({"report": {"summary": "合成协作报告", "hypotheses": [], "unknowns": ["未执行应用"]}})
        index = self.step - 2
        self.step += 1
        action = actions[min(index, len(actions) - 1)]
        if not self.with_detail and action.get("tool") == "record_finding_detail":
            return actions[-1]
        return action


@pytest.mark.parametrize("with_detail", [True, False])
def test_parallel_demo_through_web_and_report(tmp_path, with_detail):
    records, lock, barrier = [], Lock(), Barrier(3)
    review_barrier = Barrier(2) if with_detail else None
    tools = demo_tools()
    service = AuditService(AuditStore(tmp_path / "tasks.sqlite3"), ThreadPoolExecutor(max_workers=1),
                           lambda: ScriptedTeamModel(barrier, records, lock, with_detail, review_barrier), lambda r, s: tools)
    app = FastAPI()
    app.state.audit_service = service
    app.include_router(router)
    try:
        with TestClient(app) as client:
            response = client.post("/api/audits", json={"objective": "检查合成订单归属权限", "repository_id": "demo",
                "snapshot_id": "demo-v1", "max_steps": 40, "allow_remote_code": True})
            assert response.status_code == 202
            task_id = response.json()["id"]
            service.future.result(timeout=15)
            task = service.get(task_id)
            report = client.get(f"/api/audits/{task_id}/report").json()
            assert task["status"] == "needs_review", task.get("error")
            assert task["parallel_agents"] == 3
            assert len(task["agent_tasks"]) == 3
            assert all(worker["status"] == "completed" for worker in task["agent_tasks"])
            assert len(task["team_deliveries"]) == len(set(task["team_deliveries"])) == 4
            assert "agent-1:progress-1" in task["team_deliveries"]
            assert len(report["findings"]) == (2 if with_detail else 0)
            assert len(report["independentReviews"]) == (2 if with_detail else 1)
            if not with_detail:
                assert report["independentReviews"][0]["method"] == "missing_candidate_detail"
                assert not any("静态证据复核员" in messages[0]["content"] for role, messages in records)
            assert task["model_calls"] == len(records) == len(task["model_requests"])
            assert len({row["call"] for row in task["model_requests"]}) == len(records)
            expected_roles = {"main", "baseline", "architecture", "investigator"}
            if with_detail:
                expected_roles.add("review")
            assert {role for role, messages in records} == expected_roles
            for role, messages in records:
                if role != "main":
                    assert not any("子任务结果（" in message["content"] for message in messages)
                    assert "协作审计的主调查员" not in messages[0]["content"]
            assert report["completion"]["completeSecurityAudit"] is False
            assert "子Agent进度" in client.get("/audit").text
            tools.close.assert_called_once()
    finally:
        service.close()


def make_team(tmp_path, max_steps=12):
    store = AuditStore(tmp_path / "tasks.sqlite3")
    command = AuditTaskInput("测试合成协作预算", "demo", "demo-v1", max_steps=max_steps,
                             allow_remote_code=True, parallel_agents=3)
    from dataclasses import asdict
    task = store.create(asdict(command))
    store.update(task["id"], status="running", scope={"index_run_id": "demo-run", "source_snapshot_id": "demo-source"})
    team = AgentTeam(store, task["id"], MagicMock, demo_tools())
    return team, store, task["id"]


def test_budget_reservations_are_atomic(tmp_path):
    team, store, task_id = make_team(tmp_path, max_steps=7)
    def invoke(_):
        model = MagicMock()
        model.next_action.return_value = {}
        try:
            team.request(model, [], "main")
            return True
        except TeamStopped:
            return False
    try:
        with ThreadPoolExecutor(max_workers=12) as pool:
            outcomes = list(pool.map(invoke, range(25)))
        assert sum(outcomes) == 7
        assert store.get(task_id)["model_calls"] == 7
        assert sorted(row["call"] for row in store.get(task_id)["model_requests"]) == list(range(1, 8))
    finally:
        team.close()


def test_worker_progress_is_saved_and_delivered_before_worker_finishes(tmp_path):
    """阶段结果不依赖最终大JSON；子任务仍运行时主调查也能收到。"""
    team, store, task_id = make_team(tmp_path)
    evidence = {"read-1": demo_row()}
    store.update(task_id, agent_tasks=[{
        "id": "agent-1", "role": "baseline", "status": "running", "calls": 1,
        "assignment": {}, "evidence": evidence, "events": [],
    }])
    messages, main_evidence, file_reviews = [], {}, []
    try:
        receipt = team.submit_worker_progress("agent-1", result([question()]), evidence)
        assert receipt["progress_id"] == "agent-1:progress-1"
        assert store.get(task_id)["agent_tasks"][0]["status"] == "running"

        assert team.deliver(messages, main_evidence, file_reviews) == 1
        saved = store.get(task_id)
        assert saved["team_deliveries"] == ["agent-1:progress-1"]
        assert saved["baseline"]["questions"][0]["id"] == "agent-1:progress-1:question-1"
        assert "子任务阶段成果" in messages[-1]["content"]
        exported = export_audit_report(saved)
        assert exported["agentTasks"][0]["progressResults"][0]["id"] == "agent-1:progress-1"
        assert any(item["id"] == "agent-1" for item in exported["coverage"]["deferred"])
        assert team.deliver(messages, main_evidence, file_reviews) == 0
    finally:
        team.close()


@pytest.mark.parametrize("field,value", [("repository_id", "other"), ("snapshot_id", "other"),
                                         ("index_run_id", "other"), ("source_snapshot_id", "other")])
def test_worker_evidence_cannot_change_scope(tmp_path, field, value):
    team, store, task_id = make_team(tmp_path)
    row = demo_row()
    row[field] = value
    evidence = {}
    try:
        with pytest.raises(ValueError):
            team.collect_evidence("read_file", {"rows": [row]}, evidence)
        assert evidence == {}
    finally:
        team.close()


def test_result_rejects_unread_evidence():
    with pytest.raises(ModelOutputError):
        parse_work_result(result([question()]), {})


def test_cancelled_team_does_not_send_new_requests(tmp_path):
    team, store, task_id = make_team(tmp_path)
    store.update(task_id, status="cancelled")
    model = MagicMock()
    try:
        with pytest.raises(TeamStopped):
            team.request(model, [], "main")
        model.next_action.assert_not_called()
    finally:
        team.close()


def test_delivery_is_saved_with_checkpoint_and_not_repeated(tmp_path):
    team, store, task_id = make_team(tmp_path)
    row = demo_row()
    store.update(task_id, agent_tasks=[{"id": "agent-1", "role": "baseline", "status": "completed",
                 "result": result([question()]), "evidence": {"read-1": row}}])
    messages = [{"role": "system", "content": "主调查"}]
    evidence, reviews = {}, []
    try:
        assert team.deliver(messages, evidence, reviews) == 1
        saved = store.get(task_id)
        assert saved["checkpoint"]["state"]["team_deliveries"] == ["agent-1"]
        assert saved["checkpoint"]["state"]["evidence"] == evidence
        assert team.deliver(messages, evidence, reviews) == 0
        assert len(messages) == 2
        assert "content" not in json.loads(messages[1]["content"].split("：", 1)[1])["evidence_locations"][0]
        assert saved["baseline"]["questions"][0]["id"] == "agent-1:question-1"
    finally:
        team.close()


def test_parent_failure_resume_reuses_completed_workers(tmp_path):
    store = AuditStore(tmp_path / "tasks.sqlite3")
    resumed = Event()
    created_roles = []

    class Model:
        def __init__(self):
            self.role = None
            self.calls = 0

        def next_action(self, messages):
            if self.role is None:
                self.role = (json.loads(messages[1]["content"])["role"]
                             if "只读安全审计子调查员" in messages[0]["content"] else "main")
                created_roles.append((resumed.is_set(), self.role))
            self.calls += 1
            if self.role != "main":
                if self.calls == 1:
                    return {"tool": "read_file", "arguments": {"path": "OrderService.java"}}
                return {"result": result([question()] if self.role == "baseline" else [])}
            if not resumed.is_set():
                deadline = monotonic() + 5
                while monotonic() < deadline:
                    workers = store.list()[0].get("agent_tasks", [])
                    if len(workers) == 2 and all(w["status"] == "completed" for w in workers):
                        raise ModelRequestError("合成网络故障")
                    sleep(0.01)
                raise AssertionError("子任务未完成")
            return {"report": {"summary": "恢复后保留子任务结果", "hypotheses": [], "unknowns": ["仍需主调查核实"]}}

    service = AuditService(store, ThreadPoolExecutor(max_workers=1), Model, lambda r, s: demo_tools())
    try:
        parent = service.create(AuditTaskInput("合成父任务恢复检查", "demo", "demo-v1", max_steps=30,
                                               allow_remote_code=True, parallel_agents=3))
        service.future.result(timeout=10)
        assert service.get(parent["id"])["status"] == "failed"
        old_report = service.report(parent["id"])
        resumed.set()
        child = service.resume(parent["id"], max_steps=30, allow_remote_code=True)
        service.future.result(timeout=10)
        task = service.get(child["id"])
        assert task["status"] == "needs_review", task.get("error")
        assert task["team_deliveries"] == ["agent-1", "agent-2"]
        assert [role for is_resumed, role in created_roles if is_resumed] == ["main"]
        assert all(worker["calls"] == 0 and worker["prior_calls"] == 2 and worker["reused_result"]
                   for worker in task["agent_tasks"])
        assert service.report(parent["id"]) == old_report
        assert service.report(child["id"])["coverage"]["deferred"]
    finally:
        service.close()


def test_failed_worker_does_not_fail_other_worker_or_vanish(tmp_path):
    store = AuditStore(tmp_path / "tasks.sqlite3")
    class Model:
        def next_action(self, messages):
            if "只读安全审计子调查员" in messages[0]["content"]:
                if json.loads(messages[1]["content"])["role"] == "baseline":
                    raise ModelRequestError("secret must not appear")
                return {"result": result()}
            return {"report": {"summary": "合成部分报告", "hypotheses": [], "unknowns": ["基线未完成"]}}
    service = AuditService(store, ThreadPoolExecutor(max_workers=1), Model, lambda r, s: demo_tools())
    try:
        task = service.create(AuditTaskInput("合成子任务故障隔离", "demo", "demo-v1", max_steps=20,
                                             allow_remote_code=True, parallel_agents=3))
        service.future.result(timeout=10)
        report = service.report(task["id"])
        assert report["status"] == "needs_review"
        assert [w["status"] for w in report["agentTasks"]] == ["failed", "completed"]
        assert any(row["id"] == "agent-1" for row in report["coverage"]["deferred"])
        assert "secret must not appear" not in json.dumps(store.get(task["id"]))
    finally:
        service.close()


def test_cancel_during_three_requests_freezes_results(tmp_path):
    entered, release = Event(), Event()
    barrier = Barrier(3, action=entered.set)
    calls = []
    tools = demo_tools()
    class Model:
        def next_action(self, messages):
            calls.append(1)
            barrier.wait(timeout=5)
            assert release.wait(timeout=5)
            return {"tool": "read_file", "arguments": {"path": "OrderService.java"}}
    service = AuditService(AuditStore(tmp_path / "tasks.sqlite3"), ThreadPoolExecutor(max_workers=1),
                           Model, lambda r, s: tools)
    try:
        task = service.create(AuditTaskInput("合成并发取消检查", "demo", "demo-v1", max_steps=20,
                                             allow_remote_code=True, parallel_agents=3))
        assert entered.wait(timeout=5)
        service.cancel(task["id"])
        frozen = service.store.get(task["id"])
        assert service.get(task["id"])["execution_active"] is True
        assert all(w["effective_status"] == "cancelled" for w in service.get(task["id"])["agent_tasks"])
        release.set()
        service.future.result(timeout=10)
        finished = service.store.get(task["id"])
        runtime_fields = {"finished_at", "heartbeat_at", "lease_expires_at", "lease_state"}
        assert {key: value for key, value in finished.items() if key not in runtime_fields} == {
            key: value for key, value in frozen.items() if key not in runtime_fields
        }
        assert finished["finished_at"] is not None
        assert finished["heartbeat_at"] is not None
        assert finished["lease_expires_at"] is None
        assert service.get(task["id"])["execution_active"] is False
        assert len(calls) == 3
        assert not any(call.args[0] == "read_file" for call in tools.call.call_args_list)
    finally:
        release.set()
        service.close()


def test_failed_worker_can_redeliver_after_resume(tmp_path):
    resumed = Event()
    seen = []
    class Model:
        def next_action(self, messages):
            if "只读安全审计子调查员" in messages[0]["content"]:
                role = json.loads(messages[1]["content"])["role"]
                seen.append((resumed.is_set(), role))
                if role == "baseline" and not resumed.is_set():
                    raise ModelRequestError("合成首次失败")
                return {"result": result()}
            return {"report": {"summary": "合成部分报告", "hypotheses": [], "unknowns": ["不代表安全"]}}
    service = AuditService(AuditStore(tmp_path / "tasks.sqlite3"), ThreadPoolExecutor(max_workers=1),
                           Model, lambda r, s: demo_tools())
    try:
        parent = service.create(AuditTaskInput("合成失败子任务重交付", "demo", "demo-v1", max_steps=20,
                                               allow_remote_code=True, parallel_agents=3))
        service.future.result(timeout=10)
        assert "agent-1" in service.get(parent["id"])["team_deliveries"]
        resumed.set()
        child = service.resume(parent["id"], max_steps=20, allow_remote_code=True)
        service.future.result(timeout=10)
        task = service.get(child["id"])
        assert all(worker["status"] == "completed" for worker in task["agent_tasks"])
        assert len(task["team_deliveries"]) == 2
        assert task["baseline"]["status"] == "submitted_partial"
        assert [role for is_resumed, role in seen if is_resumed] == ["baseline"]
        assert task["agent_tasks"][0]["prior_calls"] == 1
    finally:
        service.close()


def test_demo_archive_excludes_answer_document():
    import io
    import zipfile
    from benchmarks.audit_quality.run_team_demo import demo_case
    from benchmarks.audit_quality.run_web_check import archive_bytes
    with zipfile.ZipFile(io.BytesIO(archive_bytes(demo_case()))) as archive:
        assert set(archive.namelist()) == {"OrderService.java", "SafeOrderService.java"}


def test_two_agent_limit_is_respected(tmp_path):
    active = 0
    peak = 0
    lock = Lock()
    class Model:
        def next_action(self, messages):
            nonlocal active, peak
            with lock:
                active += 1
                peak = max(peak, active)
            try:
                sleep(0.04)
                if "只读安全审计子调查员" in messages[0]["content"]:
                    return {"result": result()}
                return {"report": {"summary": "合成并发上限检查", "hypotheses": [], "unknowns": ["仅验证并发"]}}
            finally:
                with lock:
                    active -= 1
    service = AuditService(AuditStore(tmp_path / "tasks.sqlite3"), ThreadPoolExecutor(max_workers=1),
                           Model, lambda r, s: demo_tools())
    try:
        task = service.create(AuditTaskInput("合成两个Agent上限", "demo", "demo-v1", max_steps=20,
                                             allow_remote_code=True, parallel_agents=2))
        service.future.result(timeout=10)
        assert service.get(task["id"])["status"] == "needs_review"
        assert peak == 2
    finally:
        service.close()


def test_workers_cannot_create_grandchildren(tmp_path):
    class Model:
        def next_action(self, messages):
            if "只读安全审计子调查员" in messages[0]["content"]:
                return {"tool": "start_investigator", "arguments": {"title": "不允许的孙任务",
                    "question": "不能扩大任务树", "evidence_ids": ["invented"]}}
            return {"report": {"summary": "合成权限测试", "hypotheses": [], "unknowns": ["子任务失败"]}}
    service = AuditService(AuditStore(tmp_path / "tasks.sqlite3"), ThreadPoolExecutor(max_workers=1),
                           Model, lambda r, s: demo_tools())
    try:
        task = service.create(AuditTaskInput("合成子Agent权限检查", "demo", "demo-v1", max_steps=30,
                                             allow_remote_code=True, parallel_agents=3))
        service.future.result(timeout=10)
        workers = service.get(task["id"])["agent_tasks"]
        assert len(workers) == 2
        assert all(worker["status"] == "failed" for worker in workers)
        assert all(worker["calls"] == 3 for worker in workers)
    finally:
        service.close()


def test_link_result_to_existing_investigation_without_duplicate(tmp_path):
    team, store, task_id = make_team(tmp_path)
    store.update(task_id, baseline={"questions": [{"id": "agent-1:question-1"}]})
    investigations = [{"id": "investigation-1", "status": "supported", "baseline_question_ids": []}]
    arguments = {"investigation_id": "investigation-1", "question_ids": ["agent-1:question-1"],
                 "reason": "同一归属控制点，复用既有调查"}
    try:
        team.link_questions(arguments, investigations)
        team.link_questions(arguments, investigations)
        assert len(investigations) == 1
        assert investigations[0]["baseline_question_ids"] == ["agent-1:question-1"]
        assert investigations[0]["status"] == "supported"
        with pytest.raises(ValueError):
            team.link_questions({**arguments, "question_ids": ["invented"]}, investigations)
    finally:
        team.close()


def test_team_requires_bound_source_before_any_model_call(tmp_path):
    tools, model = MagicMock(), MagicMock()
    tools.call.side_effect = [{"total": 1}, {"repository_id": "demo", "snapshot_id": "demo-v1"}]
    service = AuditService(AuditStore(tmp_path / "tasks.sqlite3"), ThreadPoolExecutor(max_workers=1),
                           lambda: model, lambda r, s: tools)
    try:
        with pytest.raises(ValueError, match="已绑定"):
            service.create(AuditTaskInput("合成未绑定快照检查", "demo", "demo-v1", allow_remote_code=True,
                                           parallel_agents=3))
        model.next_action.assert_not_called()
        tools.close.assert_called_once()
    finally:
        service.close()
