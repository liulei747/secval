"""审计任务业务编排。控制器不直接创建模型或提交后台任务。"""

from collections.abc import Callable
import json
from concurrent.futures import Executor, Future
from dataclasses import asdict, fields
from pathlib import Path
from threading import Event, Lock, Thread
from time import sleep
from uuid import uuid4

from secval.cross_process_file_lock import CrossProcessFileLock
from secval.interfaces.audit import AuditModelPort, AuditStorePort, EvidenceToolsPort
from secval.models.audit import AuditBusyError, AuditTaskInput
from secval.services.audit_checkpoint import restore_checkpoint, restore_path_checkpoint
from secval.services.audit_report import export_audit_report
from secval.services.audit_runner import run_task
from secval.services.audit_model_call import RecordedAuditModel
from secval.services.audit_stages import record_stage
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
        if self.store.next_queued() is not None:
            with self.lock:
                self._start_worker_if_needed()

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
        """只读预检并入库排队；模型、取证工具和进程锁留给执行Worker。"""
        tools = self.tools_factory(command.repository_id, command.snapshot_id)
        try:
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
                saved = (restore_path_checkpoint(parent, scope, inventory)
                         if parent.get("path_sketches") else
                         restore_checkpoint(parent, scope, inventory))
                continuation = {**saved["state"], "checkpoint": saved,
                                    "previous_independent_reviews": parent.get("independent_reviews", []),
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
                    # Path validation is a durable ledger, not transient model
                    # context. Reuse terminal outcomes and retry only failed
                    # packets in the child task.
                    continuation["path_sketches"] = deepcopy(parent.get("path_sketches", []))
                    for sketch in continuation["path_sketches"]:
                        if sketch.get("status") in {"validation_failed", "queued_for_validation"}:
                            sketch["status"] = "queued_for_validation"
                    continuation["validation_packets"] = deepcopy(parent.get("validation_packets", []))
                    for packet in continuation["validation_packets"]:
                        if packet.get("status") in {"failed", "queued", "running"}:
                            packet.update(status="queued", error=None,
                                          prior_attempts=packet.get("prior_attempts", 0)
                                          + packet.get("attempts", 0))
                    continuation["path_validations"] = deepcopy(parent.get("path_validations", []))
                    continuation["evidence_rounds"] = deepcopy(parent.get("evidence_rounds", []))
            task = self.store.create({**asdict(command), **continuation})
            task = self.store.update(task["id"], **continuation, scope=scope, source_inventory=inventory)
            record_stage(
                self.store, task["id"], "scope_freeze", "completed", name="范围冻结",
                completed_units=4, total_units=4,
                metadata={"repository_id": command.repository_id,
                          "snapshot_id": command.snapshot_id,
                          "scope_paths": list(command.scope_paths),
                          "source_snapshot_id": scope.get("source_snapshot_id"),
                          "index_run_id": scope.get("index_run_id")},
            )
            task = self.store.get(task["id"])
        except Exception:
            tools.close()
            raise
        else:
            tools.close()
        with self.lock:
            self._start_worker_if_needed()
        return task

    def _start_worker_if_needed(self):
        if self.future is None or self.future.done():
            self.future = self.executor.submit(self._drain_queue)
            self.future.add_done_callback(self._worker_finished)

    def _worker_finished(self, finished_future):
        """Worker退出后如果队列仍有任务，继续拉起。"""
        with self.lock:
            if self.future is finished_future and self.store.next_queued() is not None:
                self._start_worker_if_needed()

    def _drain_queue(self):
        while True:
            job = self.store.next_queued()
            if job is None:
                return
            process_lock = (self.process_lock.try_acquire()
                            if self.process_lock is not None else False)
            if self.process_lock is not None and process_lock is None:
                sleep(0.2)
                continue
            current = self.store.next_queued()
            if current is None:
                if self.process_lock is not None:
                    self.process_lock.release(process_lock)
                continue
            self._execute_claimed(current["id"], current, process_lock)

    @staticmethod
    def _submit_scope_splits(team, task):
        """大项目按顶层目录拆分范围调查子任务（P2-9 第一步）。

        scope_paths 覆盖多个顶层目录时，每组大约一个并行槽位；
        单目录或无 scope_paths 不拆分，仍由主调查自行安排。
        子任务受既有 12 上限、预算预留和 start_investigator 复用约束。
        """
        scope_paths = task.get("scope_paths") or []
        if len(scope_paths) < 2:
            return
        top_dirs = sorted({path.strip("/").split("/")[0] for path in scope_paths
                           if path.strip("/")})
        if len(top_dirs) < 2:
            return
        parallel = max(1, task.get("parallel_agents", 1) - 1)
        group_size = max(1, -(-len(top_dirs) // parallel))
        for index in range(0, len(top_dirs), group_size):
            group = top_dirs[index:index + group_size]
            paths = [path for path in scope_paths
                     if path.strip("/").split("/")[0] in group]
            team.submit("scope", {"title": "范围调查：" + ", ".join(group),
                                  "question": "只调查以下范围内的入口、信任边界与控制："
                                  + json.dumps(paths, ensure_ascii=False),
                                  "evidence_ids": []})

    def _execute_claimed(self, task_id, task, process_lock):
        model = self.model_factory()
        tools = self.tools_factory(task["repository_id"], task["snapshot_id"])
        team = None
        stop_heartbeat = Event()
        heartbeat_thread = None
        try:
            if self.process_lock is not None:
                if not self.store.claim(task_id, self.worker_id, self.lease_seconds):
                    if team is not None:
                        team.close()
                    tools.close()
                    return
                heartbeat_thread = Thread(
                    target=self._keep_lease_alive,
                    args=(task_id, stop_heartbeat),
                    name=f"audit-heartbeat-{task_id[:8]}",
                    daemon=True,
                )
                heartbeat_thread.start()
            if task.get("scope_paths"):
                tools.call("restrict_scope", {"paths": task["scope_paths"]})
            if task.get("approved_config_paths"):
                tools.call("approve_config_files", {"paths": task["approved_config_paths"]})
            self.active_task_id = task_id
            if task.get("parallel_agents", 1) > 1:
                team = AgentTeam(self.store, task_id, self.model_factory, tools)
                # Determine the execution strategy before creating legacy scope
                # workers. Previously they consumed worker slots and budget even
                # when the bounded path pipeline was selected moments later.
                team.prepare_seed()
                if not team.path_pipeline_enabled:
                    self._submit_scope_splits(team, task)
                run_task(self.store, task_id, TeamModel(team, model), tools, team)
            else:
                run_task(self.store, task_id, RecordedAuditModel(model, self.store, task_id), tools)
        except Exception:
            if team is not None:
                team.close()
            tools.close()
            current = self.store.get(task_id)
            if current["status"] in ("queued", "running"):
                self.store.update(task_id, status="failed", error="任务执行失败")
            if self.process_lock is not None:
                self.store.finish_execution(task_id, self.worker_id)
                self.process_lock.release(process_lock)
            raise
        finally:
            stop_heartbeat.set()
            if heartbeat_thread is not None:
                heartbeat_thread.join(timeout=self.heartbeat_interval + 1)
            if self.process_lock is not None:
                self.store.finish_execution(task_id, self.worker_id)
                self.process_lock.release(process_lock)

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
        if hasattr(self.store, "queue_position"):
            task["queue_position"] = self.store.queue_position(task_id)
        for worker in task.get("agent_tasks", []):
            worker["effective_status"] = worker["status"]
            if task["status"] == "cancelled" and worker["status"] in ("running", "queued"):
                worker["effective_status"] = "cancelled"
        return task

    def _is_active(self, task_id):
        return self.active_task_id == task_id and self.future is not None and not self.future.done()

    def report(self, task_id: str):
        return export_audit_report(self.store.get(task_id))

    def queue_stats(self):
        """返回当前进程观察到的队列深度。"""
        if hasattr(self.store, "queue_counts"):
            return self.store.queue_counts()
        return {"queued": 0, "running": 0}

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
