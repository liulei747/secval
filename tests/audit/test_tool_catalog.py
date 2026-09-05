"""工具说明、参数及阶段权限必须来自同一份定义。"""

from unittest.mock import MagicMock

import pytest

from secval.models.audit_contracts import ModelOutputError, ToolAction
from secval.models.audit_tools import READ_TOOL_ARGUMENTS, READ_TOOL_DESCRIPTIONS, read_tool_prompt
from secval.services.audit_runner import SYSTEM
from secval.services.baseline_audit import PROMPT
from secval.services.independent_review import review_packet


def test_all_stages_share_read_tool_description():
    assert set(READ_TOOL_ARGUMENTS) == set(READ_TOOL_DESCRIPTIONS)
    assert read_tool_prompt() in SYSTEM
    assert read_tool_prompt() in PROMPT
    model = MagicMock()
    model.next_action.side_effect = RuntimeError("stop before external call")
    with pytest.raises(RuntimeError):
        review_packet(model, {"id": "i", "question": "q", "evidence_ids": []},
                      {"entry": "entry", "asset": "asset", "evidence_ids": []}, {}, tools=MagicMock())
    assert read_tool_prompt() in model.next_action.call_args.args[0][0]["content"]


def test_rating_prompts_do_not_assume_numeric_ids_are_enumerable():
    from secval.services.independent_review import PROMPT as review_prompt

    assert "数字类型ID不证明" in SYSTEM
    assert "数字类型ID不证明" in review_prompt
    assert "start_line/end_line" in SYSTEM


def test_main_and_independent_review_share_vulnerability_outcome_meaning():
    from secval.models.investigation_review import OUTCOME_GUIDANCE
    from secval.services.independent_review import PROMPT as review_prompt

    assert OUTCOME_GUIDANCE in SYSTEM
    assert OUTCOME_GUIDANCE in review_prompt
    assert "确认防护有效也应填refuted" in OUTCOME_GUIDANCE


def test_baseline_result_example_is_strict_json():
    import json

    line = next(line for line in PROMPT.splitlines() if line.startswith("基线结果格式："))
    example = json.loads(line.removeprefix("基线结果格式：").removesuffix("。"))
    assert set(example) == {"questions", "unknowns"}


@pytest.mark.parametrize("tool", READ_TOOL_ARGUMENTS)
def test_unknown_arguments_are_rejected(tool):
    with pytest.raises(ModelOutputError):
        ToolAction.parse({"tool": tool, "arguments": {"execute": "anything"}})


@pytest.mark.parametrize("tool", ["neo4j_query", "joern_query", "shell"])
def test_unconnected_tools_are_not_advertised_as_available(tool):
    assert tool not in READ_TOOL_ARGUMENTS
    with pytest.raises(ModelOutputError):
        ToolAction.parse({"tool": tool, "arguments": {}})
