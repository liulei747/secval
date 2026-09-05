"""审计任务业务编排。控制器不直接创建模型或提交后台任务。"""

from collections.abc import Callable
from concurrent.futures import Executor, Future
from dataclasses import asdict, fields
from pathlib import Path
from threading import Event, Lock, Thread
from uuid import uuid4

from secval.cross_process_file_lock import CrossProcessFileLock
from secval.interfaces.audit import AuditModelPort, AuditStorePort, EvidenceToolsPort
from secval.models.audit import AuditBusyError, AuditTaskInput
from secval.services.audit_checkpoint import restore_checkpoint
from secval.services.audit_report import export_audit_report
from secval.services.audit_runner import run_task
from secval.services.audit_model_call import RecordedAuditModel
from secval.services.agent_team import AgentTeam, TeamModel


class AuditService:
    def __init__(
        self,
        store: AuditStorePort,
        executor: Executor,
        model_factory: Callable[[], AuditModelPort],
        tools_factory: Callable[[str, str], EvidenceToolsPort],
        heartbeat_interval=5,
        lease_seconds=20,
    ):
        self.store = store
        self.executor = executor
        self.model_factory = model_factory
        self.tools_factory = tools_factory
        self.lock = Lock()
        self.future: Future | None = None
        self.active_task_id: str | None = None
        self.worker_id = uuid4().hex
        self.heartbeat_interval = heartbeat_interval
        self.lease_seconds = lease_seconds
        store_path = getattr(store, "path", None)
        self.process_lock = None
        if isinstance(store_path, (str, Path)):
            self.process_lock = CrossProcessFileLock(str(store_path) + ".lock")
        startup_lock = self.process_lock.try_acquire() if self.process_lock is not None else None
        if startup_lock is not None:
            try:
                self.store.mark_unfinished_interrupted()
            finally:
                self.process_lock.release(startup_lock)

    def create(self, command: AuditTaskInput):
        return self._create(command)

    def resume(self, task_id, *, max_steps=12, max_seconds=300, allow_remote_code=False, allow_remote_config=False):
        parent = self.store.get(task_id)
        partial_report = (parent["status"] == "needs_review"
                          and export_audit_report(parent)["completion"]["state"] == "partial_report")
        if parent["status"] not in {"interrupted", "budget_exhausted", "failed", "cancelled"} and not partial_report:
            raise ValueError("只能续跑已停止的任务，或仍有未完成检查项的部分报告")
        values = {field.name: parent[field.name] for field in fields(AuditTaskInput) if field.name in parent}
        values.update(max_steps=max_steps, max_seconds=max_seconds,
                      allow_remote_code=allow_remote_code, allow_remote_config=allow_remote_config)
        return self._create(AuditTaskInput(**values), parent=parent)

    def _create(self, command, parent=None):
        with self.lock:
            if self.future is not None and not self.future.done():
                raise AuditBusyError("已有任务在运行或等待取消，请稍后再试")
            process_lock = self.process_lock.try_acquire() if self.process_lock is not None else False
            if self.process_lock is not None and process_lock is None:
                raise AuditBusyError("其他API进程正在执行审计任务")
            try:
                model = self.model_factory()
                tools = self.tools_factory(command.repository_id, command.snapshot_id)
                if command.scope_paths:
                    tools.call("restrict_scope", {"paths": command.scope_paths})
                if command.approved_config_paths:
                    tools.call("approve_config_files", {"paths": command.approved_config_paths})
                if not tools.call("list_chunks", {})["total"]:
                    raise ValueError("指定仓库快照没有已索引代码")
                scope = tools.call("scope_info", {})
                inventory = scope.pop("_inventory", None)
                if command.parallel_agents > 1 and (not scope.get("source_snapshot_id")
                                                     or not scope.get("index_run_id") or inventory is None):
                    raise ValueError("协作审计需要已绑定的源码快照、索引批次和文件清单，请先完整建立索引")
                continuation = {}
                if parent is not None:
                    saved = restore_checkpoint(parent, scope, inventory)
                    continuation = {**saved["state"], "checkpoint": saved,
                                    "parent_task_id": parent["id"],
                                    "parent_report_submitted": parent["status"] == "needs_review",
                                    "prior_model_calls": parent.get("prior_model_calls", 0) + parent.get("model_calls", 0)}
                    if parent.get("parallel_agents", 1) > 1:
                        # 子任务可能比主检查点更新；保留各自最近的只读检查点。
                        from copy import deepcopy
                        continuation["agent_tasks"] = deepcopy(parent.get("agent_tasks", []))
                        completed = {row["id"] for row in continuation["agent_tasks"] if row["status"] == "completed"}
                        continuation["team_deliveries"] = [worker_id for worker_id in
                            continuation.get("team_deliveries", []) if worker_id in completed]
                        continuation["checkpoint"]["state"]["team_deliveries"] = continuation["team_deliveries"]
                task = self.store.create({**asdict(command), **continuation})
                task = self.store.update(task["id"], **continuation, scope=scope, source_inventory=inventory)
                self.active_task_id = task["id"]
                if command.parallel_agents > 1:
                    team = AgentTeam(self.store, task["id"], self.model_factory, tools)
                    self.future = self.executor.submit(
                        self._run_with_lock, process_lock, self.store, task["id"],
                        TeamModel(team, model), tools, team
                    )
                else:
                    self.future = self.executor.submit(
                        self._run_with_lock, process_lock, self.store, task["id"],
                        RecordedAuditModel(model, self.store, task["id"]), tools
                    )
            except Exception:
                if "tools" in locals():
                    tools.close()
                if "task" in locals():
                    self.store.update(task["id"], status="failed", error="任务调度失败")
                if self.process_lock is not None:
                    self.process_lock.release(process_lock)
                raise
            return task

    def _run_with_lock(self, process_lock, store, task_id, model, tools, team=None):
        """认领并执行完整审计，任何退出路径都会结束租约和文件锁。"""
        stop_heartbeat = Event()
        heartbeat_thread = None
        try:
            if self.process_lock is not None:
                if not store.claim(task_id, self.worker_id, self.lease_seconds):
                    if team is not None:
                        team.close()
                    tools.close()
                    return None
                heartbeat_thread = Thread(
                    target=self._keep_lease_alive,
                    args=(task_id, stop_heartbeat),
                    name=f"audit-heartbeat-{task_id[:8]}",
                    daemon=True,
                )
                heartbeat_thread.start()
            return run_task(store, task_id, model, tools, team)
        finally:
            stop_heartbeat.set()
            if heartbeat_thread is not None:
                heartbeat_thread.join(timeout=self.heartbeat_interval + 1)
            if self.process_lock is not None:
                store.finish_execution(task_id, self.worker_id)
            if self.process_lock is not None:
                self.process_lock.release(process_lock)

    def _keep_lease_alive(self, task_id, stop_heartbeat):
        """模型请求很慢时仍持续记录工作进程存活。"""
        while not stop_heartbeat.wait(self.heartbeat_interval):
            if not self.store.renew_lease(task_id, self.worker_id, self.lease_seconds):
                return

    def list(self):
        summaries = []
        for task in self.store.list():
            summary = {key: task[key] for key in ("id", "objective", "status", "repository_id", "snapshot_id")}
            summary["execution_active"] = self._is_active(task["id"])
            summaries.append(summary)
        return summaries

    def get(self, task_id: str):
        task = self.store.get(task_id)
        task["execution_active"] = self._is_active(task_id)
        for worker in task.get("agent_tasks", []):
            worker["effective_status"] = worker["status"]
            if task["status"] == "cancelled" and worker["status"] in ("running", "queued"):
                worker["effective_status"] = "cancelled"
        return task

    def _is_active(self, task_id):
        return self.active_task_id == task_id and self.future is not None and not self.future.done()

    def report(self, task_id: str):
        return export_audit_report(self.store.get(task_id))

    def cancel(self, task_id: str):
        with self.lock:
            return self.store.request_cancel(task_id)

    def recover_stale(self, task_id):
        """双重确认任务失联后收口；不会自动调用模型或建立续跑任务。"""
        with self.lock:
            task = self.store.get(task_id)
            if task.get("lease_state") != "expired":
                raise ValueError("只有租约已经过期的任务才能恢复")
            if self.process_lock is None:
                raise ValueError("当前任务存储不支持跨进程恢复")
            process_lock = self.process_lock.try_acquire()
            if process_lock is None:
                raise AuditBusyError("任务进程锁仍被持有，不能仅凭心跳过期接管")
            try:
                return self.store.recover_stale(task_id)
            finally:
                self.process_lock.release(process_lock)

    def close(self):
        self.executor.shutdown(wait=True, cancel_futures=True)
