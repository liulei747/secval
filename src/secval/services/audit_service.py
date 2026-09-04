"""审计任务业务编排。控制器不直接创建模型或提交后台任务。"""

from collections.abc import Callable
from concurrent.futures import Executor, Future
from dataclasses import asdict, fields
from threading import Lock

from secval.interfaces.audit import AuditModelPort, AuditStorePort, EvidenceToolsPort
from secval.models.audit import AuditBusyError, AuditTaskInput
from secval.services.audit_checkpoint import restore_checkpoint
from secval.services.audit_report import export_audit_report
from secval.services.audit_runner import run_task


class AuditService:
    def __init__(
        self,
        store: AuditStorePort,
        executor: Executor,
        model_factory: Callable[[], AuditModelPort],
        tools_factory: Callable[[str, str], EvidenceToolsPort],
    ):
        self.store = store
        self.executor = executor
        self.model_factory = model_factory
        self.tools_factory = tools_factory
        self.lock = Lock()
        self.future: Future | None = None

    def create(self, command: AuditTaskInput):
        return self._create(command)

    def resume(self, task_id, *, max_steps=12, max_seconds=300, allow_remote_code=False, allow_remote_config=False):
        parent = self.store.get(task_id)
        if parent["status"] not in {"interrupted", "budget_exhausted", "failed", "cancelled"}:
            raise ValueError("只能续跑已停止且未提交最终报告的任务")
        values = {field.name: parent[field.name] for field in fields(AuditTaskInput) if field.name in parent}
        values.update(max_steps=max_steps, max_seconds=max_seconds,
                      allow_remote_code=allow_remote_code, allow_remote_config=allow_remote_config)
        return self._create(AuditTaskInput(**values), parent=parent)

    def _create(self, command, parent=None):
        with self.lock:
            if self.future is not None and not self.future.done():
                raise AuditBusyError("已有任务在运行或等待取消，请稍后再试")
            model = self.model_factory()
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
                continuation = {}
                if parent is not None:
                    saved = restore_checkpoint(parent, scope, inventory)
                    continuation = {**saved["state"], "checkpoint": saved,
                                    "parent_task_id": parent["id"],
                                    "prior_model_calls": parent.get("prior_model_calls", 0) + parent.get("model_calls", 0)}
                task = self.store.create({**asdict(command), **continuation})
                task = self.store.update(task["id"], **continuation, scope=scope, source_inventory=inventory)
                self.future = self.executor.submit(
                    run_task, self.store, task["id"], model, tools
                )
            except Exception:
                tools.close()
                if "task" in locals():
                    self.store.update(task["id"], status="failed", error="任务调度失败")
                raise
            return task

    def list(self):
        return [
            {
                k: t[k]
                for k in ("id", "objective", "status", "repository_id", "snapshot_id")
            }
            for t in self.store.list()
        ]

    def get(self, task_id: str):
        return self.store.get(task_id)

    def report(self, task_id: str):
        return export_audit_report(self.store.get(task_id))

    def cancel(self, task_id: str):
        with self.lock:
            task = self.store.get(task_id)
            if task["status"] in ("queued", "running"):
                task = self.store.update(task_id, status="cancelled")
            return task

    def close(self):
        self.executor.shutdown(wait=True, cancel_futures=True)
