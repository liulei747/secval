"""请求统计不复制模型正文，失败调用也记录且不重试。"""

from unittest.mock import MagicMock

import pytest

from secval.infrastructure.audit.sqlite_audit_store import AuditStore
from secval.models.audit_contracts import ModelOutputError, ModelRequestError
from secval.services.audit_model_call import RecordedAuditModel


@pytest.mark.parametrize("failure", [None, ModelOutputError("private response", code="invalid_json"),
                                    ModelRequestError("请求超时")])
def test_only_safe_request_statistics_are_saved(tmp_path, failure):
    store = AuditStore(tmp_path / "tasks.sqlite3")
    task = store.create({"objective": "测试", "repository_id": "test", "snapshot_id": "test"})
    store.update(task["id"], model_calls=1, phase="baseline", status="running")
    model = MagicMock()
    model.last_response_info = {"prompt_tokens": 12, "reasoning_content": "private reasoning",
                                "api_key": "private key", "completion_tokens": True}
    model.next_action.return_value = {"tool": "list_files", "arguments": {}}
    model.next_action.side_effect = failure
    recorded = RecordedAuditModel(model, store, task["id"])
    if failure is None:
        recorded.next_action([{"role": "user", "content": "private input"}])
    else:
        with pytest.raises(type(failure)):
            recorded.next_action([{"role": "user", "content": "private input"}])
    saved = store.get(task["id"])
    assert saved["status"] == "running"
    assert len(saved["model_requests"]) == 1
    row = saved["model_requests"][0]
    assert row["prompt_tokens"] == 12
    assert "completion_tokens" not in row
    assert "private" not in str(row)
    model.next_action.assert_called_once()
