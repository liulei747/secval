"""流式返回完整后才能执行动作；断流、截断和供应端错误必须停止。"""

import io
import json
from unittest.mock import patch

import pytest

from secval.config.audit_settings import load_audit_settings
from secval.infrastructure.audit.api_audit_model import AuditModel
from secval.infrastructure.audit.stream_response import read_stream_response
from secval.models.audit_contracts import ModelOutputError, ModelRequestError


class StreamResponse(io.BytesIO):
    headers = {"Content-Type": "text/event-stream; charset=utf-8"}


def event(delta, finish=None):
    value = {"choices": [{"index": 0, "delta": delta, "finish_reason": finish}]}
    return ("data: " + json.dumps(value, ensure_ascii=False) + "\n\n").encode()


def run(body):
    model = AuditModel("https://example.invalid", "secret", "test", stream=True)
    with patch("secval.infrastructure.audit.api_audit_model.urlopen", return_value=StreamResponse(body)) as send:
        result = model.next_action([])
    assert json.loads(send.call_args.args[0].data)["stream"] is True
    send.assert_called_once()
    return result, model.last_response_info


def test_join_content_without_saving_thinking():
    body = b": heartbeat\n\n" + event({"reasoning_content": "private"})
    body += event({"content": '{"name":'}) + event({"content": '"中文"}'}, "stop")
    body += b'data: {"choices":[],"usage":{"prompt_tokens":12}}\n\ndata: [DONE]\n\n'
    result, info = run(body)
    assert result == {"name": "中文"}
    assert info["reasoning_characters"] == 7
    assert info["prompt_tokens"] == 12
    assert info["headers_ms"] >= 0
    assert info["first_data_ms"] >= 0
    assert "private" not in str(info)


@pytest.mark.parametrize("body,code", [
    (event({"content": "{}"}, "stop"), "invalid_response"),
    (event({"content": "{}"}) + b"data: [DONE]\n\n", "invalid_response"),
    (event({"content": "{}"}, "length") + b"data: [DONE]\n\n", "truncated"),
    (b'data: {"error":"secret"}\n\n', "invalid_response"),
    (b'data: secret\n\n', "invalid_response"),
    (event({"content": "not json"}, "stop") + b"data: [DONE]\n\n", "invalid_json"),
    (event({"tool_calls": ["secret"]}), "invalid_response"),
    (b":" + b"x" * 2_000_000, "response_too_large"),
], ids=["disconnected", "missing-finish", "truncated", "provider-error", "bad-event",
        "bad-json", "unexpected-tool", "oversized"])
def test_bad_stream_never_returns_action(body, code):
    with pytest.raises(ModelOutputError) as caught:
        run(body)
    assert caught.value.code == code
    assert "secret" not in str(caught.value)


def test_body_timeout_is_safe():
    response = StreamResponse(b"")
    with patch.object(response, "readline", side_effect=TimeoutError("secret")):
        with patch("secval.infrastructure.audit.api_audit_model.urlopen", return_value=response) as send:
            with pytest.raises(ModelRequestError, match="读取响应正文"):
                AuditModel("https://example.invalid", "secret", "test", stream=True).next_action([])
    send.assert_called_once()


def test_stream_does_not_silently_fall_back():
    response = StreamResponse(b"{}")
    response.headers = {"Content-Type": "application/json"}
    with patch("secval.infrastructure.audit.api_audit_model.urlopen", return_value=response) as send:
        with pytest.raises(ModelOutputError, match="未自动重试"):
            AuditModel("https://example.invalid", "secret", "test", stream=True).next_action([])
    send.assert_called_once()


@pytest.mark.parametrize("value,expected", [("true", True), ("false", False)])
def test_stream_setting(monkeypatch, value, expected):
    monkeypatch.setenv("SECVAL_AUDIT_STREAM", value)
    assert load_audit_settings().stream is expected


def test_invalid_stream_setting(monkeypatch):
    monkeypatch.setenv("SECVAL_AUDIT_STREAM", "maybe")
    with pytest.raises(ValueError):
        load_audit_settings()


def test_late_stream_data_cannot_return_action():
    response = StreamResponse(event({"content": "{}"}, "stop") + b"data: [DONE]\n\n")
    with patch("secval.infrastructure.audit.stream_response.monotonic", side_effect=[1, 301]):
        with pytest.raises(TimeoutError):
            read_stream_response(response, {}, 0, 300)
