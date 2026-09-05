"""审计任务的跨进程锁不能误伤仍在运行的任务。"""

from concurrent.futures import ThreadPoolExecutor
from threading import Event
import time
from unittest.mock import MagicMock

import pytest

from secval.cross_process_file_lock import CrossProcessFileLock
from secval.infrastructure.audit.sqlite_audit_store import AuditStore
from secval.models.audit import AuditBusyError, AuditTaskInput
from secval.services.audit_service import AuditService


def test_second_service_does_not_interrupt_task_owned_by_another_process(tmp_path):
    database = tmp_path / "tasks.sqlite3"
    first_store = AuditStore(database)
    task = first_store.create({"objective": "测试跨进程审计锁"})
    first_store.update(task["id"], status="running")

    outside_lock = CrossProcessFileLock(str(database) + ".lock")
    handle = outside_lock.try_acquire()
    assert handle is not None
    second = AuditService(AuditStore(database), MagicMock(), MagicMock(), MagicMock())
    try:
        assert second.store.get(task["id"])["status"] == "running"
        command = AuditTaskInput(
            objective="验证第二个服务不能启动审计",
            repository_id="repo",
            snapshot_id="snapshot",
            allow_remote_code=True,
        )
        with pytest.raises(AuditBusyError, match="其他API进程"):
            second.create(command)
    finally:
        second.close()
        outside_lock.release(handle)


def test_service_marks_unowned_running_task_interrupted(tmp_path):
    database = tmp_path / "tasks.sqlite3"
    store = AuditStore(database)
    task = store.create({"objective": "测试重启恢复"})
    store.update(task["id"], status="running")

    restarted = AuditService(AuditStore(database), MagicMock(), MagicMock(), MagicMock())
    try:
        saved = restarted.store.get(task["id"])
        assert saved["status"] == "interrupted"
        assert "服务重启中断" in saved["error"]
    finally:
        restarted.close()


def test_heartbeat_and_cross_process_cancel_do_not_overwrite_audit_data(tmp_path):
    database = tmp_path / "tasks.sqlite3"
    request_started = Event()
    release_request = Event()
    model = MagicMock()

    def wait_for_release(messages):
        request_started.set()
        assert release_request.wait(timeout=5)
        return {"report": {"summary": "不会在取消后提交", "hypotheses": [], "unknowns": ["测试"]}}

    model.next_action.side_effect = wait_for_release
    tools = MagicMock()

    def tool_call(name, arguments):
        if name == "list_chunks":
            return {"total": 1, "rows": []}
        if name == "scope_info":
            return {"repository_id": "repo", "snapshot_id": "snapshot",
                    "source_snapshot_id": "source", "index_run_id": "run", "_inventory": []}
        raise AssertionError(f"未预期的工具：{name}")

    tools.call.side_effect = tool_call
    store = AuditStore(database)
    service = AuditService(
        store,
        ThreadPoolExecutor(max_workers=1),
        lambda: model,
        lambda repository_id, snapshot_id: tools,
        heartbeat_interval=0.02,
        lease_seconds=1,
    )
    try:
        task = service.create(AuditTaskInput(
            objective="测试审计运行信息与调查正文分开保存",
            repository_id="repo",
            snapshot_id="snapshot",
            allow_remote_code=True,
            independent_baseline=False,
            parallel_agents=1,
        ))
        assert request_started.wait(timeout=5)
        first_heartbeat = service.get(task["id"])["heartbeat_at"]
        store.update(task["id"], test_marker="必须保留")

        renewed = False
        for _ in range(20):
            time.sleep(0.02)
            if service.get(task["id"])["heartbeat_at"] != first_heartbeat:
                renewed = True
                break
        assert renewed is True

        # 新建Store模拟请求落到另一个API进程，只写独立运行表。
        cancelling_store = AuditStore(database)
        cancelled_view = cancelling_store.request_cancel(task["id"])
        assert cancelled_view["status"] == "cancelled"
        assert cancelled_view["test_marker"] == "必须保留"

        release_request.set()
        service.future.result(timeout=5)
        saved = service.get(task["id"])
        assert saved["status"] == "cancelled"
        assert saved["test_marker"] == "必须保留"
        assert saved["worker_id"] == service.worker_id
        assert saved["attempt"] == 1
        assert saved["lease_expires_at"] is None
        assert saved["finished_at"] is not None
    finally:
        release_request.set()
        service.close()


def test_cancel_before_worker_claim_is_finalized(tmp_path):
    store = AuditStore(tmp_path / "tasks.sqlite3")
    task = store.create({"objective": "测试认领前取消"})
    assert store.request_cancel(task["id"])["status"] == "cancelled"

    assert store.claim(task["id"], "worker-1", 20) is False
    assert store.finish_execution(task["id"], "worker-1") is True
    saved = store.get(task["id"])
    assert saved["status"] == "cancelled"
    assert saved["finished_at"] is not None
    assert saved["lease_expires_at"] is None
