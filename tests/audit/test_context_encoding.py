"""中文编码优化只改变JSON写法，不改变源码和检查点内容。"""

import json
from copy import deepcopy

import pytest

from secval.services.audit_context import compact_context, tool_reply_for_model


@pytest.mark.parametrize("prefix", ["", "工具数据：", "不可信工具数据：",
                                    "独立基线问题（非结论）与已读证据："])
def test_json_encoding_preserves_values(prefix):
    value = {"说明": "中文证据", "content": r'"\u4e2d"', "nested": ["方法"]}
    messages = [{"role": "user", "content": prefix + json.dumps(value)}]
    original = deepcopy(messages)
    result = compact_context(messages)
    assert messages == original
    assert json.loads(result[0]["content"][len(prefix):]) == value
    assert "中文证据" in result[0]["content"]
    assert len(result[0]["content"]) < len(messages[0]["content"])


@pytest.mark.parametrize("content", [r'源码包含\u4e2d', '未知前缀：{"x": "中文"}', '{broken'])
def test_non_json_text_is_unchanged(content):
    messages = [{"role": "user", "content": content}]
    assert compact_context(messages) == messages


def test_record_receipt_keeps_identity_without_repeating_analysis():
    result = {"candidateDetail": {"id": "detail-1", "investigation_id": "investigation-1",
                                 "status": "needs_review", "summary": "完整描述"}}
    original = deepcopy(result)
    reply = tool_reply_for_model("record_finding_detail", result)
    assert result == original
    assert reply["candidateDetail"] == {"id": "detail-1", "investigation_id": "investigation-1",
                                        "status": "needs_review"}
    assert "独立验证" in reply["note"]


@pytest.mark.parametrize("name,result", [
    ("read_file", {"rows": [{"content": "完整源码"}]}),
    ("audit_progress", {"pendingInvestigations": ["调查1"]}),
    ("record_finding_detail", {"error": "固定校验错误"}),
])
def test_reads_progress_and_errors_are_not_shortened(name, result):
    assert tool_reply_for_model(name, result) == result


def test_old_read_source_is_projected_to_reread_location():
    action = {"tool": "read_file", "arguments": {"path": "src/app.py"}}
    row = {"evidence_id": "file-1:0:40000", "chunk_id": "file-1",
           "relative_path": "src/app.py", "start_line": 1, "end_line": 900,
           "content_sha256": "a" * 64, "content": "x" * 40000}
    messages = [
        {"role": "system", "content": "audit"},
        {"role": "assistant", "content": json.dumps(action)},
        {"role": "user", "content": "工具数据：" + json.dumps({"rows": [row]})},
        {"role": "user", "content": "next"},
        {"role": "assistant", "content": "recent"},
        {"role": "user", "content": "continue"},
    ]

    result = compact_context(messages, threshold=1000, keep_recent=3)

    assert "x" * 100 not in result[2]["content"]
    assert "file-1:0:40000" in result[2]["content"]
    assert "src/app.py" in result[2]["content"]
    assert len(result[2]["content"]) < 1000
