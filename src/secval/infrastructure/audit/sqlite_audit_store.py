"""SQLite审计任务存储；中断任务不会冒充已经完成。"""

import json
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from threading import Lock
from uuid import uuid4

from secval.task_lease import lease_state


def _now():
    return datetime.now(timezone.utc).isoformat()


def _future_time(seconds):
    return (datetime.now(timezone.utc) + timedelta(seconds=seconds)).isoformat()


class AuditStore:
    def __init__(self, path):
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        self.path = str(path)
        self.lock = Lock()
        with self.connect() as db:
            db.execute(
                "CREATE TABLE IF NOT EXISTS tasks (id TEXT PRIMARY KEY, data TEXT NOT NULL)"
            )
            db.execute("""CREATE TABLE IF NOT EXISTS audit_task_runtime (
                task_id TEXT PRIMARY KEY, worker_id TEXT, heartbeat_at TEXT,
                lease_expires_at TEXT, attempt INTEGER NOT NULL DEFAULT 0,
                cancel_requested INTEGER NOT NULL DEFAULT 0
            )""")
            db.execute("INSERT OR IGNORE INTO audit_task_runtime (task_id) SELECT id FROM tasks")

    def mark_unfinished_interrupted(self):
        """把没有运行进程负责的旧任务标为中断。

        调用方必须先取得审计跨进程锁，避免误伤其他进程的任务。
        """
        with self.lock:
            with self.connect() as db:
                rows = db.execute(
                    "SELECT tasks.id,tasks.data,audit_task_runtime.cancel_requested "
                    "FROM tasks JOIN audit_task_runtime ON audit_task_runtime.task_id=tasks.id"
                ).fetchall()
                for task_id, task_json, cancel_requested in rows:
                    task = json.loads(task_json)
                    if task["status"] not in ("queued", "running"):
                        continue
                    final_status = "cancelled" if cancel_requested else "interrupted"
                    stop_reason = "user_cancelled" if cancel_requested else "service_restarted"
                    error = None if cancel_requested else (
                        "服务重启中断；可尝试从检查点续跑，未绑定或版本改变时需新建任务"
                    )
                    workers = task.get("agent_tasks", [])
                    for worker in workers:
                        if worker["status"] in ("queued", "running"):
                            worker.update(status="interrupted", stop_reason=stop_reason)
                    task.update(status=final_status, agent_tasks=workers, error=error,
                                finished_at=_now())
                    db.execute("UPDATE tasks SET data=? WHERE id=?", (json.dumps(task), task_id))
                    db.execute(
                        "UPDATE audit_task_runtime SET heartbeat_at=?, lease_expires_at=NULL "
                        "WHERE task_id=?", (_now(), task_id)
                    )

    @contextmanager
    def connect(self):
        # Connection的with只处理提交/回滚，不会关闭连接。
        connection = sqlite3.connect(self.path)
        connection.execute("PRAGMA busy_timeout=5000")
        try:
            with connection:
                yield connection
        finally:
            connection.close()

    def create(self, request):
        created_at = _now()
        task = {
            "id": uuid4().hex,
            **request,
            "status": "queued",
            "events": [],
            "evidence": {},
            "report": None,
            "error": None,
            "created_at": created_at,
            "started_at": None,
            "finished_at": None,
            "coverage": "partial:仅限已索引代码块；不代表完整源文件或项目覆盖",
        }
        with self.connect() as db:
            db.execute(
                "INSERT INTO tasks VALUES (?, ?)", (task["id"], json.dumps(task))
            )
            db.execute("INSERT INTO audit_task_runtime (task_id) VALUES (?)", (task["id"],))
        return task

    def get(self, task_id):
        with self.connect() as db:
            row = db.execute("SELECT data FROM tasks WHERE id=?", (task_id,)).fetchone()
            runtime = db.execute(
                "SELECT worker_id,heartbeat_at,lease_expires_at,attempt,cancel_requested "
                "FROM audit_task_runtime WHERE task_id=?", (task_id,)
            ).fetchone()
        if row is None:
            raise KeyError(task_id)
        task = json.loads(row[0])
        if runtime is not None:
            stored_status = task["status"]
            task.update(worker_id=runtime[0], heartbeat_at=runtime[1],
                        lease_expires_at=runtime[2], attempt=runtime[3],
                        cancel_requested=bool(runtime[4]))
            task["lease_state"] = lease_state(stored_status, runtime[2])
            if runtime[4] and task["status"] in ("queued", "running"):
                # 调查线程看到 cancelled 后会停止，不再覆盖已经保存的证据。
                task["status"] = "cancelled"
        else:
            task["lease_state"] = "missing" if task["status"] in ("queued", "running") else "inactive"
        return task

    def list(self):
        with self.connect() as db:
            task_ids = [row[0] for row in db.execute("SELECT id FROM tasks ORDER BY rowid DESC")]
        return [self.get(task_id) for task_id in task_ids]

    def update(self, task_id, **fields):
        with self.lock:
            task = self.get(task_id)
            if task["status"] == "cancelled":
                return task
            status = fields.get("status")
            if status == "running" and task.get("started_at") is None:
                fields["started_at"] = _now()
            if status in {"needs_review", "budget_exhausted", "failed", "interrupted", "cancelled"}:
                fields["finished_at"] = _now()
            task.update(fields)
            for runtime_field in ("worker_id", "heartbeat_at", "lease_expires_at",
                                  "attempt", "cancel_requested", "lease_state"):
                task.pop(runtime_field, None)
            with self.connect() as db:
                db.execute(
                    "UPDATE tasks SET data=? WHERE id=?", (json.dumps(task), task_id)
                )
            return task

    def claim(self, task_id, worker_id, lease_seconds):
        """原子认领排队任务；运行信息写入独立表，不碰调查正文。"""
        started_at = _now()
        with self.lock:
            with self.connect() as db:
                db.execute("BEGIN IMMEDIATE")
                row = db.execute("SELECT data FROM tasks WHERE id=?", (task_id,)).fetchone()
                if row is None:
                    raise KeyError(task_id)
                task = json.loads(row[0])
                runtime = db.execute(
                    "SELECT worker_id,cancel_requested FROM audit_task_runtime WHERE task_id=?",
                    (task_id,),
                ).fetchone()
                if task["status"] != "queued" or runtime[0] is not None or runtime[1]:
                    return False
                task.update(status="running", started_at=started_at)
                db.execute("UPDATE tasks SET data=? WHERE id=?", (json.dumps(task), task_id))
                db.execute(
                    "UPDATE audit_task_runtime SET worker_id=?,heartbeat_at=?,lease_expires_at=?,"
                    "attempt=attempt+1 WHERE task_id=?",
                    (worker_id, started_at, _future_time(lease_seconds), task_id),
                )
        return True

    def renew_lease(self, task_id, worker_id, lease_seconds):
        """仅更新独立运行表，绝不重写审计证据JSON。"""
        heartbeat_at = _now()
        with self.connect() as db:
            changed = db.execute(
                "UPDATE audit_task_runtime SET heartbeat_at=?,lease_expires_at=? "
                "WHERE task_id=? AND worker_id=? AND lease_expires_at IS NOT NULL",
                (heartbeat_at, _future_time(lease_seconds), task_id, worker_id),
            ).rowcount
        return changed == 1

    def request_cancel(self, task_id):
        """跨进程记录取消信号，不重写可能正在变化的调查正文。"""
        with self.connect() as db:
            row = db.execute("SELECT data FROM tasks WHERE id=?", (task_id,)).fetchone()
            if row is None:
                raise KeyError(task_id)
            task = json.loads(row[0])
            if task["status"] in ("queued", "running"):
                db.execute("UPDATE audit_task_runtime SET cancel_requested=1 WHERE task_id=?",
                           (task_id,))
        return self.get(task_id)

    def finish_execution(self, task_id, worker_id):
        """结束租约；若收到取消信号，此时把取消状态写回任务正文。"""
        finished_at = _now()
        with self.lock:
            with self.connect() as db:
                db.execute("BEGIN IMMEDIATE")
                runtime = db.execute(
                    "SELECT worker_id,cancel_requested FROM audit_task_runtime WHERE task_id=?",
                    (task_id,),
                ).fetchone()
                if runtime is None:
                    return False
                if runtime[0] != worker_id and not (runtime[0] is None and runtime[1]):
                    return False
                if runtime[1]:
                    row = db.execute("SELECT data FROM tasks WHERE id=?", (task_id,)).fetchone()
                    task = json.loads(row[0])
                    task.update(status="cancelled", finished_at=finished_at)
                    db.execute("UPDATE tasks SET data=? WHERE id=?", (json.dumps(task), task_id))
                db.execute(
                    "UPDATE audit_task_runtime SET heartbeat_at=?,lease_expires_at=NULL "
                    "WHERE task_id=?", (finished_at, task_id),
                )
        return True

    def recover_stale(self, task_id):
        """把已确认失联的任务收口；调用方还必须先确认进程锁无人持有。"""
        finished_at = _now()
        with self.lock:
            with self.connect() as db:
                db.execute("BEGIN IMMEDIATE")
                row = db.execute("SELECT data FROM tasks WHERE id=?", (task_id,)).fetchone()
                runtime = db.execute(
                    "SELECT lease_expires_at,cancel_requested FROM audit_task_runtime WHERE task_id=?",
                    (task_id,),
                ).fetchone()
                if row is None or runtime is None:
                    raise KeyError(task_id)
                task = json.loads(row[0])
                if lease_state(task["status"], runtime[0]) != "expired":
                    raise ValueError("任务租约状态已经变化，请刷新后重试")
                if runtime[1]:
                    final_status = "cancelled"
                    error = None
                    stop_reason = "user_cancelled"
                else:
                    final_status = "interrupted"
                    error = "任务租约过期且没有进程持锁；请核对模型请求状态后显式续跑"
                    stop_reason = "lease_expired"
                workers = task.get("agent_tasks", [])
                for worker in workers:
                    if worker["status"] in ("queued", "running"):
                        worker.update(status="interrupted", stop_reason=stop_reason)
                task.update(status=final_status, error=error, agent_tasks=workers,
                            finished_at=finished_at)
                db.execute("UPDATE tasks SET data=? WHERE id=?", (json.dumps(task), task_id))
                db.execute(
                    "UPDATE audit_task_runtime SET heartbeat_at=?,lease_expires_at=NULL "
                    "WHERE task_id=?", (finished_at, task_id),
                )
        return self.get(task_id)
