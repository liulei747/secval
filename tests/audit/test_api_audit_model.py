"""完全离线验证请求错误分类、脱敏和不自动重试。"""

import json
import socket
import ssl
from http.client import IncompleteRead
from unittest.mock import MagicMock, patch
from urllib.error import HTTPError, URLError

import pytest

from secval.infrastructure.audit.api_audit_model import AuditModel
from secval.models.audit_contracts import ModelRequestError
from secval.models.audit_contracts import ModelOutputError


@pytest.mark.parametrize("error, expected", [
    (TimeoutError("secret"), "请求超时"),
    (URLError(TimeoutError("secret")), "请求超时"),
    (URLError(socket.gaierror("secret")), "域名解析失败"),
    (URLError(ssl.SSLError("secret")), "TLS握手或证书错误"),
    (ConnectionResetError("secret"), "连接失败或中断"),
    (URLError("secret"), "网络请求失败"),
    (HTTPError("secret", 429, "secret", {}, None), "HTTP 429"),
])
def test_request_errors_are_safe_and_not_retried(error, expected):
    model = AuditModel("https://example.invalid/v1", "secret", "test")
    with patch("secval.infrastructure.audit.api_audit_model.urlopen", side_effect=error) as send:
        with pytest.raises(ModelRequestError) as caught:
            model.next_action([])
    assert expected in str(caught.value)
    assert "secret" not in str(caught.value)
    assert "example.invalid" not in str(caught.value)
    send.assert_called_once()


@pytest.mark.parametrize("error", [TimeoutError("secret"), IncompleteRead(b"secret")])
def test_body_failure_reports_read_phase(error):
    response = MagicMock()
    response.__enter__.return_value = response
    response.read.side_effect = error
    with patch("secval.infrastructure.audit.api_audit_model.urlopen", return_value=response):
        with pytest.raises(ModelRequestError) as caught:
            AuditModel("https://example.invalid/v1", "secret", "test").next_action([])
    assert "读取响应正文" in str(caught.value)
    assert "secret" not in str(caught.value)


def test_success_keeps_request_contract():
    response = MagicMock()
    response.__enter__.return_value = response
    response.read.return_value = json.dumps({"choices": [{
        "finish_reason": "stop", "message": {"content": '{"tool":"list_files","arguments":{}}'}
    }]}).encode()
    with patch("secval.infrastructure.audit.api_audit_model.urlopen", return_value=response) as send:
        result = AuditModel("https://example.invalid/v1", "secret", "test").next_action([])
    assert result == {"tool": "list_files", "arguments": {}}
    assert send.call_args.kwargs["timeout"] == 120


@pytest.mark.parametrize("payload, code", [
    (b"secret", "invalid_response"),
    (b'{"choices": [{"message": {"content": null}}]}', "missing_content"),
    (b'{"choices": [{"finish_reason": "length"}]}', "truncated"),
    (b'{"choices": [{"message": {"content": "secret"}}]}', "invalid_json"),
    (b'{"choices": [{"message": {"content": "[]"}}]}', "not_object"),
])
def test_output_failure_codes_do_not_include_raw_response(payload, code):
    response = MagicMock()
    response.__enter__.return_value = response
    response.read.return_value = payload
    with patch("secval.infrastructure.audit.api_audit_model.urlopen", return_value=response):
        with pytest.raises(ModelOutputError) as caught:
            AuditModel("https://example.invalid", "secret", "test").next_action([])
    assert caught.value.code == code
    assert "secret" not in str(caught.value)


def test_response_statistics_exclude_text():
    model = AuditModel("https://example.invalid", "secret", "test")
    response = MagicMock()
    response.__enter__.return_value = response
    response.read.return_value = json.dumps({
        "choices": [{"message": {"content": "{}", "reasoning_content": "private"}}],
        "usage": {"prompt_tokens": 20, "completion_tokens": 10, "total_tokens": 30,
                  "secret": "must not copy"},
    }).encode()
    with patch("secval.infrastructure.audit.api_audit_model.urlopen", return_value=response):
        model.next_action([])
    assert model.last_response_info == {"prompt_tokens": 20, "completion_tokens": 10,
                                       "total_tokens": 30, "reasoning_characters": 7, "content_characters": 2}


@pytest.mark.parametrize("thinking", [None, "enabled", "disabled"])
def test_thinking_extension_is_opt_in(thinking):
    response = MagicMock()
    response.__enter__.return_value = response
    response.read.return_value = b'{"choices":[{"message":{"content":"{}"}}]}'
    with patch("secval.infrastructure.audit.api_audit_model.urlopen", return_value=response) as send:
        AuditModel("https://example.invalid", "test", "test", thinking=thinking).next_action([])
    body = json.loads(send.call_args.args[0].data)
    if thinking is None:
        assert "thinking" not in body
    else:
        assert body["thinking"] == {"type": thinking}


def test_json_error_explains_position_without_echoing_response():
    response = MagicMock()
    response.__enter__.return_value = response
    response.read.return_value = json.dumps({"choices": [{"message": {"content": '{} secret'}}]}).encode()
    with patch("secval.infrastructure.audit.api_audit_model.urlopen", return_value=response):
        with pytest.raises(ModelOutputError) as caught:
            AuditModel("https://example.invalid", "secret", "test").next_action([])
    assert "第1行第4列" in str(caught.value)
    assert "多余内容" in str(caught.value)
    assert "secret" not in str(caught.value)
