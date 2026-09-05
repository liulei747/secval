"""基线失败必须保留可识别原因，不泄露原文，不自动重试。"""

from dataclasses import asdict
from unittest.mock import MagicMock

import pytest

from secval.infrastructure.audit.sqlite_audit_store import AuditStore
from secval.models.audit import AuditTaskInput, EvidenceServiceError
from secval.models.audit_contracts import ModelOutputError, ModelRequestError
from secval.services.audit_runner import run_task


@pytest.mark.parametrize("failure, reason", [
    (ModelOutputError("private model text"), "model_output_invalid"),
    (ModelRequestError("审计API请求超时"), "model_request_failed"),
    (EvidenceServiceError("private model text"), "evidence_service_failed"),
])
def test_baseline_failure_is_saved_without_retry(tmp_path, failure, reason):
    store = AuditStore(tmp_path / "tasks.sqlite3")
    command = AuditTaskInput(objective="检查合成订单访问控制", repository_id="test",
                             snapshot_id="test", allow_remote_code=True, max_steps=9)
    task = store.create(asdict(command))
    model = MagicMock()
    model.next_action.side_effect = failure
    tools = MagicMock()
    run_task(store, task["id"], model, tools)
    saved = store.get(task["id"])
    assert saved["status"] == "failed"
    assert saved["stop_reason"] == reason
    assert saved["model_calls"] == 1
    assert "private model text" not in saved["error"]
    model.next_action.assert_called_once()
    tools.close.assert_called_once()


def test_three_consecutive_main_format_errors_stop(tmp_path):
    store = AuditStore(tmp_path / "tasks.sqlite3")
    command = AuditTaskInput(objective="合成连续错误检查", repository_id="test", snapshot_id="test",
                             allow_remote_code=True, max_steps=9, independent_baseline=False)
    task = store.create(asdict(command))
    model = MagicMock()
    model.next_action.side_effect = ModelOutputError("invalid")
    tools = MagicMock()
    run_task(store, task["id"], model, tools)
    saved = store.get(task["id"])
    assert saved["status"] == "failed"
    assert saved["stop_reason"] == "format_limit"
    assert saved["model_calls"] == 3
    assert saved["correction_count"] == 3
    assert saved["consecutive_corrections"] == 3
    tools.call.assert_not_called()


@pytest.mark.parametrize("failure", [ModelRequestError("请求超时"), ModelOutputError("无效回复"),
                                    EvidenceServiceError("服务不可用")])
def test_late_failure_does_not_overwrite_user_cancellation(tmp_path, failure):
    store = AuditStore(tmp_path / "tasks.sqlite3")
    command = AuditTaskInput(objective="合成取消优先检查", repository_id="test", snapshot_id="test",
                             allow_remote_code=True, max_steps=9)
    task = store.create(asdict(command))

    def cancel_then_fail(messages):
        store.update(task["id"], status="cancelled")
        raise failure

    model = MagicMock()
    model.next_action.side_effect = cancel_then_fail
    tools = MagicMock()
    run_task(store, task["id"], model, tools)
    assert store.get(task["id"])["status"] == "cancelled"
    model.next_action.assert_called_once()
    tools.close.assert_called_once()
