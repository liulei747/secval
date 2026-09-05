"""后台索引任务保存结果，并允许中断任务显式续跑。"""

from threading import Event
import os
from pathlib import Path
import subprocess
import sqlite3
import sys
import time

import pytest

from secval.cross_process_file_lock import CrossProcessFileLock
from secval.services.index_job_service import (
    IndexJobService,
    IndexJobStore,
)


def test_index_job_returns_immediately_and_saves_result(tmp_path):
    release = Event()

    def run_index(request, progress):
        progress("生成测试索引")
        assert release.wait(timeout=5)
        return {"index_run_id": "run-1", "repository_id": request["repository_id"]}

    service = IndexJobService(IndexJobStore(tmp_path / "jobs.sqlite3"), run_index)
    try:
        job = service.create({"repository_id": "repo"})
        assert job["status"] == "queued"
        release.set()
        service.future.result(timeout=5)
        saved = service.get(job["id"])
        assert saved["status"] == "completed"
        assert saved["stage"] == "已完成"
        assert saved["result"]["index_run_id"] == "run-1"
        assert saved["created_at"] is not None
        assert saved["started_at"] is not None
        assert saved["finished_at"] is not None
        assert saved["worker_id"] == service.worker_id
        assert saved["heartbeat_at"] is not None
        assert saved["lease_expires_at"] is None
        assert saved["attempt"] == 1
        assert [item["stage"] for item in saved["stage_history"]] == [
            "等待执行", "准备索引", "生成测试索引", "已完成"
        ]
    finally:
        release.set()
        service.close()


def test_restart_marks_running_job_interrupted_and_resume_creates_child(tmp_path):
    database = tmp_path / "jobs.sqlite3"
    store = IndexJobStore(database)
    parent = store.create({"repository_id": "repo"})
    store.update(parent["id"], status="running")

    restarted_store = IndexJobStore(database)
    service = IndexJobService(restarted_store, lambda request, progress: {"ok": True})
    try:
        assert restarted_store.get(parent["id"])["status"] == "interrupted"
        assert restarted_store.get(parent["id"])["stage"] == "已中断"
        child = service.resume(parent["id"])
        service.future.result(timeout=5)
        assert child["parent_id"] == parent["id"]
        assert service.get(child["id"])["status"] == "completed"
    finally:
        service.close()


def test_second_service_queues_job_while_first_process_holds_lock(tmp_path):
    database = tmp_path / "jobs.sqlite3"
    release = Event()
    started = Event()

    def slow_index(request, progress):
        started.set()
        assert release.wait(timeout=5)
        return {"ok": True}

    first = IndexJobService(IndexJobStore(database), slow_index)
    first_job = first.create({"repository_id": "first"})
    assert started.wait(timeout=5)
    second = IndexJobService(IndexJobStore(database), lambda request, progress: {"ok": True})
    try:
        second_job = second.create({"repository_id": "second"})
        assert second.get(second_job["id"])["status"] == "queued"
        assert second.get(second_job["id"])["queue_position"] == 1
        with pytest.raises(ValueError, match="索引任务"):
            second.run_exclusive(lambda: "should-not-run")
        assert first.get(first_job["id"])["status"] == "running"
        release.set()
        first.future.result(timeout=5)
        second.future.result(timeout=5)
        assert first.get(first_job["id"])["status"] == "completed"
        assert second.get(second_job["id"])["status"] == "completed"
    finally:
        release.set()
        first.close()
        second.close()


def test_file_lock_is_exclusive_between_real_python_processes(tmp_path):
    lock_path = tmp_path / "index.lock"
    lock = CrossProcessFileLock(lock_path)
    handle = lock.try_acquire()
    assert handle is not None
    check = (
        "import sys; "
        "from secval.cross_process_file_lock import CrossProcessFileLock; "
        "lock=CrossProcessFileLock(sys.argv[1]); "
        "handle=lock.try_acquire(); "
        "sys.exit(0 if handle is None else 1)"
    )
    child_environment = os.environ.copy()
    source_directory = str(Path(__file__).resolve().parents[2] / "src")
    old_python_path = child_environment.get("PYTHONPATH", "")
    child_environment["PYTHONPATH"] = source_directory + os.pathsep + old_python_path
    try:
        blocked = subprocess.run([sys.executable, "-c", check, str(lock_path)], check=False,
                                 env=child_environment)
        assert blocked.returncode == 0
    finally:
        lock.release(handle)

    acquired = subprocess.run([sys.executable, "-c", check, str(lock_path)], check=False,
                              env=child_environment)
    assert acquired.returncode == 1


def test_failure_records_the_stage_where_it_happened(tmp_path):
    def fail_index(request, progress):
        progress("写入测试向量")
        raise RuntimeError("测试失败")

    service = IndexJobService(IndexJobStore(tmp_path / "jobs.sqlite3"), fail_index)
    try:
        job = service.create({"repository_id": "repo"})
        service.future.result(timeout=5)
        saved = service.get(job["id"])
        assert saved["status"] == "failed"
        assert saved["stage"] == "执行失败"
        assert saved["failed_stage"] == "写入测试向量"
        assert saved["finished_at"] is not None
        assert saved["stage_history"][-1]["stage"] == "执行失败"
    finally:
        service.close()


def test_old_database_is_upgraded_without_inventing_old_times(tmp_path):
    database = tmp_path / "old.sqlite3"
    with sqlite3.connect(database) as db:
        db.execute("""CREATE TABLE index_jobs (
            id TEXT PRIMARY KEY, parent_id TEXT, status TEXT NOT NULL,
            request_json TEXT NOT NULL, result_json TEXT, error TEXT,
            stage TEXT NOT NULL DEFAULT '等待执行'
        )""")
        db.execute("INSERT INTO index_jobs VALUES (?, ?, ?, ?, ?, ?, ?)",
                   ("old-job", None, "completed", "{}", "{}", None, "等待执行"))

    saved = IndexJobStore(database).get("old-job")
    assert saved["status"] == "completed"
    assert saved["created_at"] is None
    assert saved["stage_history"] == []
    assert saved["worker_id"] is None
    assert saved["attempt"] == 0


def test_running_job_stops_at_next_safe_stage_and_can_resume(tmp_path):
    reached_slow_step = Event()
    release_slow_step = Event()

    def slow_index(request, progress):
        progress("生成代码向量")
        reached_slow_step.set()
        assert release_slow_step.wait(timeout=5)
        progress("写入OpenSearch")
        return {"ok": True}

    service = IndexJobService(IndexJobStore(tmp_path / "jobs.sqlite3"), slow_index)
    try:
        job = service.create({"repository_id": "repo"})
        assert reached_slow_step.wait(timeout=5)
        cancelling = service.cancel(job["id"])
        assert cancelling["status"] == "cancelling"
        assert cancelling["stage"] == "等待安全停止"
        release_slow_step.set()
        service.future.result(timeout=5)
        cancelled = service.get(job["id"])
        assert cancelled["status"] == "cancelled"
        assert cancelled["stage"] == "已取消"
        assert cancelled["result"] is None

        resumed = service.resume(job["id"])
        service.future.result(timeout=5)
        assert resumed["parent_id"] == job["id"]
        assert service.get(resumed["id"])["status"] == "completed"
    finally:
        release_slow_step.set()
        service.close()


def test_cancel_does_not_overwrite_queued_status_when_worker_starts(tmp_path):
    store = IndexJobStore(tmp_path / "jobs.sqlite3")
    job = store.create({"repository_id": "repo"})
    store.request_cancel(job["id"])
    assert store.claim(job["id"], "worker-1", 20) is False
    assert store.get(job["id"])["status"] == "cancelled"


def test_cancel_is_rejected_after_new_index_commit_starts(tmp_path):
    store = IndexJobStore(tmp_path / "jobs.sqlite3")
    job = store.create({"repository_id": "repo"})
    assert store.claim(job["id"], "worker-1", 20) is True
    store.update_stage(job["id"], "绑定新索引与源码")
    with pytest.raises(ValueError, match="提交阶段"):
        store.request_cancel(job["id"])


def test_long_step_renews_lease_without_waiting_for_next_stage(tmp_path):
    running = Event()
    release = Event()

    def long_step(request, progress):
        progress("生成代码向量")
        running.set()
        assert release.wait(timeout=5)
        return {"ok": True}

    service = IndexJobService(
        IndexJobStore(tmp_path / "jobs.sqlite3"),
        long_step,
        heartbeat_interval=0.02,
        lease_seconds=1,
    )
    try:
        job = service.create({"repository_id": "repo"})
        assert running.wait(timeout=5)
        first_heartbeat = service.get(job["id"])["heartbeat_at"]
        renewed = False
        for _ in range(20):
            time.sleep(0.02)
            current = service.get(job["id"])
            if current["heartbeat_at"] != first_heartbeat:
                renewed = True
                break
        assert renewed is True
        assert current["worker_id"] == service.worker_id
        assert current["lease_expires_at"] is not None
        assert service.store.renew_lease(job["id"], "wrong-worker", 1) is False
    finally:
        release.set()
        service.close()


def test_restart_recovers_unfinished_job_older_than_list_page(tmp_path):
    database = tmp_path / "jobs.sqlite3"
    store = IndexJobStore(database)
    old_job = store.create({"repository_id": "old-running-job"})
    assert store.claim(old_job["id"], "old-worker", 1) is True
    for number in range(100):
        completed = store.create({"repository_id": f"completed-{number}"})
        store.update(completed["id"], status="completed", result={"ok": True})

    service = IndexJobService(IndexJobStore(database), lambda request, progress: {"ok": True})
    try:
        assert service.get(old_job["id"])["status"] == "interrupted"
    finally:
        service.close()


def test_service_start_processes_existing_queue_without_new_request(tmp_path):
    database = tmp_path / "jobs.sqlite3"
    store = IndexJobStore(database)
    queued = store.create({"repository_id": "queued-before-restart"})

    service = IndexJobService(IndexJobStore(database), lambda request, progress: {"ok": True})
    try:
        service.future.result(timeout=5)
        saved = service.get(queued["id"])
        assert saved["status"] == "completed"
        assert saved["attempt"] == 1
    finally:
        service.close()
