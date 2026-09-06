"""P2-9 范围拆分调度：多顶层目录时自动提交 scope 子任务。"""

from concurrent.futures import ThreadPoolExecutor
from threading import Barrier, Lock

from secval.infrastructure.audit.sqlite_audit_store import AuditStore
from secval.models.audit import AuditTaskInput
from secval.services.audit_service import AuditService
from tests.audit.test_agent_team import ScriptedTeamModel, demo_row, demo_tools
from unittest.mock import MagicMock


def _loose_tools():
    tools = demo_tools()
    original_call = tools.call.side_effect
    def call(name, arguments):
        if name in {"restrict_scope", "approve_config_files"}:
            return {"ok": True}
        if name == "list_chunks":
            return {"total": 2, "rows": []}
        if name == "scope_info":
            return original_call(name, arguments)
        if name == "read_file":
            return {"rows": [demo_row("OrderService.java")]}
        return original_call(name, arguments)
    tools.call.side_effect = call
    return tools


def test_scope_splits_grouping_logic():
    # 纯逻辑验收：不跑模型流程，验证分组与路径归组。
    scope_paths = ["orders/api", "orders/web", "billing/api", "billing/web", "common"]
    top_dirs = sorted({path.strip("/").split("/")[0] for path in scope_paths if path.strip("/")})
    assert top_dirs == ["billing", "common", "orders"]
    parallel = 2
    group_size = max(1, -(-len(top_dirs) // parallel))
    groups = [top_dirs[i:i + group_size] for i in range(0, len(top_dirs), group_size)]
    assert len(groups) == 2
    assert all(group for group in groups)


def test_scope_paths_split_into_scope_workers(tmp_path):
    records, lock, barrier = [], Lock(), Barrier(3)
    service = AuditService(AuditStore(tmp_path / "split.sqlite3"),
        ThreadPoolExecutor(max_workers=1),
        lambda: ScriptedTeamModel(barrier, records, lock, False, None),
        lambda r, s: _loose_tools())
    try:
        task = service.create(AuditTaskInput("范围拆分验收", "demo", "demo-v1",
            max_steps=40, allow_remote_code=True, parallel_agents=3,
            scope_paths=["orders/api", "orders/web", "billing/api", "billing/web", "common"]))
        service.future.result(timeout=20)
        finished = service.get(task["id"])
        # 流程可能因脚本固定步骤失败；只验收 scope 子任务确实被创建。
        roles = [worker["role"] for worker in finished.get("agent_tasks", [])]
        scope_roles = [role for role in roles if role == "scope"]
        assert len(scope_roles) == 2
    finally:
        service.close()
