"""租约状态和显式失联恢复。"""

from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock

import pytest

from secval.cross_process_file_lock import CrossProcessFileLock
from secval.infrastructure.audit.sqlite_audit_store import AuditStore
from secval.services.audit_service import AuditService
from secval.services.index_job_service import IndexJobService, IndexJobStore, IndexProcessBusyError
from secval.task_lease import lease_state


def iso_after(seconds):
    return (datetime.now(timezone.utc) + timedelta(seconds=seconds)).isoformat()


def test_lease_state_names_are_unambiguous():
    assert lease_state("queued", None) == "pending"
    assert lease_state("running", None) == "missing"
    assert lease_state("running", iso_after(30)) == "healthy"
    assert lease_state("running", iso_after(-30)) == "expired"
    assert lease_state("running", "not-a-time") == "invalid"
    assert lease_state("completed", None) == "inactive"


def test_expired_index_job_requires_free_process_lock_before_recovery(tmp_path):
    store = IndexJobStore(tmp_path / "index.sqlite3")
    service = IndexJobService(store, lambda request, progress: {"ok": True})
    job = store.create({"repository_id": "repo"})
    assert store.claim(job["id"], "lost-worker", -1) is True

    outside_lock = CrossProcessFileLock(store.database + ".lock")
    handle = outside_lock.try_acquire()
    assert handle is not None
    try:
        with pytest.raises(IndexProcessBusyError, match="进程锁仍被持有"):
            service.recover_stale(job["id"])
    finally:
        outside_lock.release(handle)

    recovered = service.recover_stale(job["id"])
    assert recovered["status"] == "interrupted"
    assert recovered["lease_state"] == "inactive"
    assert "显式续跑" in recovered["error"]
    service.close()


def test_expired_audit_is_closed_without_automatic_model_call(tmp_path):
    store = AuditStore(tmp_path / "audit.sqlite3")
    model_factory = MagicMock()
    service = AuditService(
        store,
        ThreadPoolExecutor(max_workers=1),
        model_factory,
        MagicMock(),
    )
    task = store.create({"objective": "测试失联恢复"})
    assert store.claim(task["id"], "lost-worker", -1) is True

    recovered = service.recover_stale(task["id"])
    assert recovered["status"] == "interrupted"
    assert recovered["lease_state"] == "inactive"
    assert "显式续跑" in recovered["error"]
    model_factory.assert_not_called()
    service.close()


def test_expired_cancelled_audit_finishes_as_cancelled(tmp_path):
    store = AuditStore(tmp_path / "audit.sqlite3")
    service = AuditService(store, ThreadPoolExecutor(max_workers=1), MagicMock(), MagicMock())
    task = store.create({"objective": "测试失联取消"})
    assert store.claim(task["id"], "lost-worker", -1) is True
    store.request_cancel(task["id"])

    recovered = service.recover_stale(task["id"])
    assert recovered["status"] == "cancelled"
    assert recovered["error"] is None
    assert recovered["lease_state"] == "inactive"
    service.close()
