"""验收脚本不能泄漏答案、无限调用或改动正式取证索引。"""

from unittest.mock import MagicMock

import pytest

from benchmarks.audit_quality.cases import CASES, model_input
from benchmarks.audit_quality.run_agent_check import CountedModel
from secval.infrastructure.audit.index_evidence_tools import EvidenceTools
from secval.models.audit_contracts import ModelRequestError
from secval.models.audit import EvidenceServiceError
from opensearchpy.exceptions import NotFoundError


def test_budget_counts_failed_call_without_retry():
    model = MagicMock()
    model.next_action.side_effect = ModelRequestError("测试故障")
    counted = CountedModel(model, 1)
    with pytest.raises(ModelRequestError):
        counted.next_action([])
    with pytest.raises(ModelRequestError, match="额度"):
        counted.next_action([])
    assert counted.calls == 1
    model.next_action.assert_called_once()


def test_evidence_view_uses_explicit_test_index():
    client = MagicMock()
    client.transport.perform_request.return_value = {"pit_id": "test-pit"}
    tools = EvidenceTools(client, "repo", "snapshot", index_name="secval-agent-check-test")
    tools._open_view()
    assert client.transport.perform_request.call_args.args[1] == "/secval-agent-check-test/_search/point_in_time"
    assert client.transport.perform_request.call_args.kwargs["params"]["keep_alive"] == "2h"
    tools.close()


def test_missing_view_does_not_reopen_or_fall_back_to_live_index():
    client = MagicMock()
    client.search.side_effect = NotFoundError(404, "private upstream detail")
    tools = EvidenceTools(client, "repo", "snapshot")
    tools.pit_id = "existing-view"
    with pytest.raises(EvidenceServiceError) as caught:
        tools.call("list_chunks", {})
    assert "private" not in str(caught.value)
    client.transport.perform_request.assert_not_called()
    client.search.assert_called_once()
    assert client.search.call_args.kwargs["body"]["pit"] == {"id": "existing-view", "keep_alive": "2h"}


@pytest.mark.parametrize("case", CASES)
def test_model_inputs_do_not_include_expected_answer(case):
    inputs = model_input(case)
    assert set(inputs) == {"objective", "security_context", "files"}
    assert inputs["files"] == case["files"]
    assert "expected" not in inputs
