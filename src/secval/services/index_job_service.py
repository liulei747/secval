"""把耗时索引放到后台，并把进度状态保存到 SQLite。"""

import json
import logging
import sqlite3
from contextlib import contextmanager
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from pathlib import Path
from threading import Event, Lock, Thread
from uuid import uuid4

from secval.cross_process_file_lock import CrossProcessFileLock
from secval.task_lease import lease_state

logger = logging.getLogger(__name__)


def _now():
    """返回便于 Web 接口直接展示的 UTC 时间。"""
    return datetime.now(timezone.utc).isoformat()


def _future_time(seconds):
    """计算租约到期时间。"""
    return (datetime.now(timezone.utc) + timedelta(seconds=seconds)).isoformat()


class IndexProcessBusyError(ValueError):
    """其他进程或兼容接口正在建索引。"""


class IndexJobCancelled(Exception):
    """用户要求在提交新索引前安全停止任务。"""


class IndexJobStore:
    def __init__(self, database):
        self.database = str(database)
        Path(self.database).parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as db:
            db.execute("""CREATE TABLE IF NOT EXISTS index_jobs (
                id TEXT PRIMARY KEY, parent_id TEXT, status TEXT NOT NULL,
                request_json TEXT NOT NULL, result_json TEXT, error TEXT,
                stage TEXT NOT NULL DEFAULT '等待执行',
                created_at TEXT, started_at TEXT, finished_at TEXT,
                failed_stage TEXT, stage_history_json TEXT NOT NULL DEFAULT '[]',
                worker_id TEXT, heartbeat_at TEXT, lease_expires_at TEXT,
                attempt INTEGER NOT NULL DEFAULT 0
            )""")
            columns = {row[1] for row in db.execute("PRAGMA table_info(index_jobs)")}
            missing_columns = {
                "stage": "TEXT NOT NULL DEFAULT '等待执行'",
                "created_at": "TEXT",
                "started_at": "TEXT",
                "finished_at": "TEXT",
                "failed_stage": "TEXT",
                "stage_history_json": "TEXT NOT NULL DEFAULT '[]'",
                "worker_id": "TEXT",
                "heartbeat_at": "TEXT",
                "lease_expires_at": "TEXT",
                "attempt": "INTEGER NOT NULL DEFAULT 0",
            }
            for name, definition in missing_columns.items():
                if name not in columns:
                    db.execute(f"ALTER TABLE index_jobs ADD COLUMN {name} {definition}")

    def mark_unfinished_interrupted(self):
        """只能在已取得跨进程索引锁时调用。"""
        with self._connect() as db:
            job_ids = [row[0] for row in db.execute(
                "SELECT id FROM index_jobs WHERE status IN ('running', 'cancelling')"
            )]
        for job_id in job_ids:
            self.update(job_id, status="interrupted", error="服务重启，任务需要续跑")

    @contextmanager
    def _connect(self):
        connection = sqlite3.connect(self.database)
        try:
            with connection:
                yield connection
        finally:
            connection.close()

    def create(self, request, parent_id=None):
        created_at = _now()
        job = {"id": uuid4().hex, "parent_id": parent_id, "status": "queued", "stage": "等待执行",
               "request": request, "result": None, "error": None,
               "created_at": created_at, "started_at": None, "finished_at": None,
               "failed_stage": None,
               "stage_history": [{"stage": "等待执行", "time": created_at}],
               "worker_id": None, "heartbeat_at": None, "lease_expires_at": None,
               "attempt": 0, "lease_state": "pending"}
        with self._connect() as db:
            db.execute("INSERT INTO index_jobs "
                       "(id,parent_id,status,request_json,result_json,error,stage,created_at,"
                       "started_at,finished_at,failed_stage,stage_history_json) "
                       "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                       (job["id"], parent_id, job["status"],
                        json.dumps(request, ensure_ascii=False), None, None, job["stage"], created_at,
                        None, None, None, json.dumps(job["stage_history"], ensure_ascii=False)))
        return self.get(job["id"])

    def update(self, job_id, *, status, result=None, error=None):
        current = self.get(job_id)
        stage_names = {"completed": "已完成", "failed": "执行失败", "interrupted": "已中断",
                       "cancelling": "等待安全停止", "cancelled": "已取消"}
        stage = stage_names.get(status, current["stage"])
        changed_at = _now()
        history = current["stage_history"]
        if not history or history[-1]["stage"] != stage:
            history.append({"stage": stage, "time": changed_at})
        started_at = current["started_at"]
        if status == "running" and started_at is None:
            started_at = changed_at
        finished_at = current["finished_at"]
        if status in {"completed", "failed", "interrupted", "cancelled"}:
            finished_at = changed_at
        failed_stage = current["failed_stage"]
        if status == "failed":
            failed_stage = current["stage"]
        heartbeat_at = current["heartbeat_at"]
        lease_expires_at = current["lease_expires_at"]
        if status in {"completed", "failed", "interrupted", "cancelled"}:
            heartbeat_at = changed_at
            lease_expires_at = None
        with self._connect() as db:
            db.execute("UPDATE index_jobs SET status=?, result_json=?, error=?, stage=?, "
                       "started_at=?, finished_at=?, failed_stage=?, stage_history_json=?, "
                       "heartbeat_at=?, lease_expires_at=? WHERE id=?",
                       (status, json.dumps(result, ensure_ascii=False) if result is not None else None,
                        error, stage, started_at, finished_at, failed_stage,
                        json.dumps(history, ensure_ascii=False), heartbeat_at, lease_expires_at, job_id))
        return self.get(job_id)

    def update_stage(self, job_id, stage):
        current = self.get(job_id)
        history = current["stage_history"]
        if not history or history[-1]["stage"] != stage:
            history.append({"stage": stage, "time": _now()})
        with self._connect() as db:
            db.execute("UPDATE index_jobs SET stage=?, stage_history_json=? WHERE id=?",
                       (stage, json.dumps(history, ensure_ascii=False), job_id))

    def claim(self, job_id, worker_id, lease_seconds):
        """由一个工作进程原子认领仍在排队的任务。"""
        started_at = _now()
        lease_expires_at = _future_time(lease_seconds)
        with self._connect() as db:
            changed = db.execute(
                "UPDATE index_jobs SET status='running', started_at=?, worker_id=?, "
                "heartbeat_at=?, lease_expires_at=?, attempt=attempt+1 "
                "WHERE id=? AND status='queued'",
                (started_at, worker_id, started_at, lease_expires_at, job_id)
            ).rowcount
        return changed == 1

    def renew_lease(self, job_id, worker_id, lease_seconds):
        """只有当前认领者可以续租运行中或正在取消的任务。"""
        heartbeat_at = _now()
        with self._connect() as db:
            changed = db.execute(
                "UPDATE index_jobs SET heartbeat_at=?, lease_expires_at=? "
                "WHERE id=? AND worker_id=? AND status IN ('running', 'cancelling')",
                (heartbeat_at, _future_time(lease_seconds), job_id, worker_id)
            ).rowcount
        return changed == 1

    def request_cancel(self, job_id):
        """保存取消请求，让真正执行任务的进程在阶段边界处理。"""
        job = self.get(job_id)
        if job["status"] in {"completed", "failed", "interrupted", "cancelled"}:
            return job
        if job["status"] == "queued":
            return self.update(job_id, status="cancelled")
        if job["stage"] in {"绑定新索引与源码", "清理旧索引"}:
            raise ValueError("新索引已经进入提交阶段，为保证数据一致性不能取消")
        return self.update(job_id, status="cancelling")

    def get(self, job_id):
        with self._connect() as db:
            row = db.execute("SELECT id,parent_id,status,request_json,result_json,error,stage,"
                             "created_at,started_at,finished_at,failed_stage,stage_history_json,"
                             "worker_id,heartbeat_at,lease_expires_at,attempt "
                             "FROM index_jobs WHERE id=?", (job_id,)).fetchone()
        if row is None:
            raise KeyError(job_id)
        job = {"id": row[0], "parent_id": row[1], "status": row[2], "stage": row[6],
                "request": json.loads(row[3]),
                "result": json.loads(row[4]) if row[4] else None, "error": row[5],
                "created_at": row[7], "started_at": row[8], "finished_at": row[9],
                "failed_stage": row[10],
                "stage_history": json.loads(row[11]) if row[11] else [],
                "worker_id": row[12], "heartbeat_at": row[13],
                "lease_expires_at": row[14], "attempt": row[15]}
        job["lease_state"] = lease_state(job["status"], job["lease_expires_at"])
        job["queue_position"] = self.queue_position(job_id) if job["status"] == "queued" else None
        return job

    def queue_position(self, job_id):
        """按创建顺序计算当前任务在等待队列中的位置。"""
        with self._connect() as db:
            row = db.execute("SELECT rowid,status FROM index_jobs WHERE id=?", (job_id,)).fetchone()
            if row is None:
                raise KeyError(job_id)
            if row[1] != "queued":
                return None
            return db.execute(
                "SELECT COUNT(*) FROM index_jobs WHERE status='queued' AND rowid<=?", (row[0],)
            ).fetchone()[0]

    def list(self):
        with self._connect() as db:
            ids = [row[0] for row in db.execute("SELECT id FROM index_jobs ORDER BY rowid DESC LIMIT 100")]
        return [self.get(job_id) for job_id in ids]

    def next_queued(self):
        """读取最早排队任务；真正归属仍由claim的条件更新决定。"""
        with self._connect() as db:
            row = db.execute(
                "SELECT id FROM index_jobs WHERE status='queued' ORDER BY rowid LIMIT 1"
            ).fetchone()
        return self.get(row[0]) if row is not None else None


class IndexJobService:
    def __init__(self, store, run_index, *, heartbeat_interval=5, lease_seconds=20):
        self.store = store
        self.run_index = run_index
        self.executor = ThreadPoolExecutor(max_workers=1)
        self.lock = Lock()
        self.future = None
        self.closed = False
        self.stop_event = Event()
        self.worker_id = uuid4().hex
        self.heartbeat_interval = heartbeat_interval
        self.lease_seconds = lease_seconds
        self.process_lock = CrossProcessFileLock(store.database + ".lock")
        # 能拿到锁说明没有其他进程正在建索引，此时才能恢复遗留状态。
        startup_lock = self.process_lock.try_acquire()
        if startup_lock is not None:
            try:
                self.store.mark_unfinished_interrupted()
            finally:
                self.process_lock.release(startup_lock)
        if self.store.next_queued() is not None:
            with self.lock:
                self._start_worker_if_needed()

    def create(self, request, parent_id=None):
        job = self.store.create(request, parent_id)
        with self.lock:
            self._start_worker_if_needed()
        return job

    def _start_worker_if_needed(self):
        if self.closed:
            raise RuntimeError("索引任务服务已经关闭")
        if self.future is None or self.future.done():
            self.future = self.executor.submit(self._drain_queue)
            self.future.add_done_callback(self._worker_finished)

    def _worker_finished(self, finished_future):
        """处理Worker退出与创建请求交错的极短竞态。"""
        with self.lock:
            if (self.future is finished_future and not self.closed
                    and self.store.next_queued() is not None):
                self._start_worker_if_needed()

    def _drain_queue(self):
        """依次处理共享数据库中最早的排队任务。"""
        while not self.closed:
            job = self.store.next_queued()
            if job is None:
                return
            process_lock = self.process_lock.try_acquire()
            if process_lock is None:
                # 另一进程正在执行。短暂等待后重新查队列，任务不会丢失。
                if self.stop_event.wait(0.2):
                    return
                continue
            current = self.store.next_queued()
            if current is None:
                self.process_lock.release(process_lock)
                continue
            self._run(current["id"], current["request"], process_lock)

    def run_exclusive(self, operation):
        """让旧的同步接口也遵守同一把跨进程锁。"""
        with self.lock:
            if self.future is not None and not self.future.done():
                raise IndexProcessBusyError("已有后台索引任务正在运行")
            process_lock = self.process_lock.try_acquire()
            if process_lock is None:
                raise IndexProcessBusyError("其他API进程正在执行索引任务")
            try:
                return operation()
            finally:
                self.process_lock.release(process_lock)

    def resume(self, job_id):
        parent = self.store.get(job_id)
        if parent["status"] not in {"failed", "interrupted", "cancelled"}:
            raise ValueError("只能续跑失败、中断或已经取消的索引任务")
        return self.create(parent["request"], parent["id"])

    def cancel(self, job_id):
        return self.store.request_cancel(job_id)

    def recover_stale(self, job_id):
        """确认租约和进程锁都已失效后，把任务收口但不自动重跑。"""
        with self.lock:
            job = self.store.get(job_id)
            if job["lease_state"] != "expired":
                raise ValueError("只有租约已经过期的任务才能恢复")
            process_lock = self.process_lock.try_acquire()
            if process_lock is None:
                raise IndexProcessBusyError("任务进程锁仍被持有，不能仅凭心跳过期接管")
            try:
                current = self.store.get(job_id)
                if current["lease_state"] != "expired":
                    raise ValueError("任务租约状态已经变化，请刷新后重试")
                if current["status"] == "cancelling":
                    return self.store.update(job_id, status="cancelled")
                return self.store.update(
                    job_id,
                    status="interrupted",
                    error="任务租约过期且没有进程持锁；请确认外部服务状态后显式续跑",
                )
            finally:
                self.process_lock.release(process_lock)

    def _run(self, job_id, request, process_lock):
        stop_heartbeat = Event()
        heartbeat_thread = None
        try:
            if not self.store.claim(job_id, self.worker_id, self.lease_seconds):
                if self.store.get(job_id)["status"] == "cancelling":
                    self.store.update(job_id, status="cancelled")
                return
            heartbeat_thread = Thread(
                target=self._keep_lease_alive,
                args=(job_id, stop_heartbeat),
                name=f"index-heartbeat-{job_id[:8]}",
                daemon=True,
            )
            heartbeat_thread.start()
            self.store.update_stage(job_id, "准备索引")
            try:
                def progress(stage):
                    self._stop_if_cancelled(job_id)
                    self.store.update_stage(job_id, stage)

                result = self.run_index(request, progress)
                self._stop_if_cancelled(job_id)
            except IndexJobCancelled:
                self.store.update(job_id, status="cancelled")
                return
            except Exception as error:
                # 不保存第三方异常细节，避免路径、凭据或响应正文进入Web接口。
                logger.exception("后台索引任务失败：%s", job_id)
                self.store.update(job_id, status="failed", error=f"索引失败：{type(error).__name__}")
                return
            self.store.update(job_id, status="completed", result=result)
        finally:
            stop_heartbeat.set()
            if heartbeat_thread is not None:
                heartbeat_thread.join(timeout=self.heartbeat_interval + 1)
            self.process_lock.release(process_lock)

    def _keep_lease_alive(self, job_id, stop_heartbeat):
        """长步骤运行时定时续租，不等待步骤结束才记录存活。"""
        while not stop_heartbeat.wait(self.heartbeat_interval):
            if not self.store.renew_lease(job_id, self.worker_id, self.lease_seconds):
                return

    def _stop_if_cancelled(self, job_id):
        if self.store.get(job_id)["status"] == "cancelling":
            raise IndexJobCancelled()

    def get(self, job_id):
        return self.store.get(job_id)

    def list(self):
        return self.store.list()

    def close(self):
        with self.lock:
            self.closed = True
            self.stop_event.set()
        self.executor.shutdown(wait=True, cancel_futures=True)
