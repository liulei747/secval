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


def test_native_tool_call_is_converted_to_internal_action():
    response = MagicMock()
    response.__enter__.return_value = response
    response.read.return_value = json.dumps({"choices": [{
        "finish_reason": "tool_calls",
        "message": {"content": None, "tool_calls": [{
            "id": "call-1", "type": "function",
            "function": {"name": "read_file", "arguments": '{"path":"src/app.py"}'},
        }]},
    }]}).encode()
    with patch("secval.infrastructure.audit.api_audit_model.urlopen", return_value=response) as send:
        result = AuditModel(
            "https://example.invalid", "secret", "test", tool_protocol="native"
        ).next_action([])

    assert result == {"tool": "read_file", "arguments": {"path": "src/app.py"}}
    body = json.loads(send.call_args.args[0].data)
    assert body["tool_choice"] == "auto"
    read_file = next(tool for tool in body["tools"] if tool["function"]["name"] == "read_file")
    assert read_file["function"]["parameters"]["required"] == ["path"]


def test_native_tool_result_uses_tool_call_id_on_next_request():
    first_response = MagicMock()
    first_response.__enter__.return_value = first_response
    first_response.read.return_value = json.dumps({"choices": [{
        "message": {"content": None, "tool_calls": [{
            "id": "call-2", "type": "function",
            "function": {"name": "list_files", "arguments": "{}"},
        }]},
    }]}).encode()
    second_response = MagicMock()
    second_response.__enter__.return_value = second_response
    second_response.read.return_value = b'{"choices":[{"message":{"content":"{}"}}]}'
    model = AuditModel(
        "https://example.invalid", "secret", "test", tool_protocol="native"
    )
    with patch(
        "secval.infrastructure.audit.api_audit_model.urlopen",
        side_effect=[first_response, second_response],
    ) as send:
        action = model.next_action([])
        messages = [
            {"role": "assistant", "content": json.dumps(action)},
            {"role": "user", "content": '工具数据：{"rows":[]}'},
        ]
        model.next_action(messages)

    body = json.loads(send.call_args_list[1].args[0].data)
    assert body["messages"][-2]["tool_calls"][0]["id"] == "call-2"
    assert body["messages"][-1] == {
        "role": "tool", "tool_call_id": "call-2",
        "name": "list_files", "content": '{"rows":[]}',
    }


def test_native_tool_pair_is_restored_after_process_restart():
    """新模型实例没有内存状态时，仍能从检查点的通用记录恢复工具协议。"""

    model = AuditModel(
        "https://example.invalid", "secret", "test", tool_protocol="native"
    )
    messages = [
        {"role": "system", "content": "test"},
        {"role": "assistant", "content": json.dumps({
            "tool": "read_file", "arguments": {"path": "src/app.py"}
        })},
        {"role": "user", "content": "工具数据：{\"content\":\"source\"}"},
        {"role": "user", "content": "从已落盘主调查边界续跑"},
    ]

    restored = model._messages_for_request(messages)

    tool_call = restored[1]["tool_calls"][0]
    assert restored[1]["role"] == "assistant"
    assert tool_call["function"]["name"] == "read_file"
    assert json.loads(tool_call["function"]["arguments"]) == {"path": "src/app.py"}
    assert restored[2] == {
        "role": "tool",
        "tool_call_id": tool_call["id"],
        "name": "read_file",
        "content": "{\"content\":\"source\"}",
    }
    assert restored[3] == messages[3]


def test_native_restart_does_not_restore_unavailable_tool():
    """续跑后的任务权限缩小时，旧工具记录不能绕过当前能力范围。"""

    model = AuditModel(
        "https://example.invalid", "secret", "test", tool_protocol="native"
    )
    model.set_available_read_tools(["read_chunk"])
    messages = [
        {"role": "assistant", "content": json.dumps({
            "tool": "read_file", "arguments": {"path": "src/app.py"}
        })},
        {"role": "user", "content": "工具数据：{}"},
    ]

    assert model._messages_for_request(messages) == messages


def test_native_mode_rejects_multiple_tool_calls():
    response = MagicMock()
    response.__enter__.return_value = response
    call = {"id": "one", "type": "function",
            "function": {"name": "list_files", "arguments": "{}"}}
    response.read.return_value = json.dumps({"choices": [{
        "message": {"content": None, "tool_calls": [call, {**call, "id": "two"}]},
    }]}).encode()
    with patch("secval.infrastructure.audit.api_audit_model.urlopen", return_value=response):
        with pytest.raises(ModelOutputError, match="每轮只允许一个"):
            AuditModel(
                "https://example.invalid", "secret", "test", tool_protocol="native"
            ).next_action([])


def test_native_mode_cannot_be_combined_with_streaming():
    with pytest.raises(ValueError, match="原生工具协议"):
        AuditModel(
            "https://example.invalid", "secret", "test",
            tool_protocol="native", stream=True,
        )


def test_native_tools_are_limited_to_current_task_capabilities():
    response = MagicMock()
    response.__enter__.return_value = response
    response.read.return_value = b'{"choices":[{"message":{"content":"{}"}}]}'
    model = AuditModel(
        "https://example.invalid", "secret", "test", tool_protocol="native"
    )
    model.set_available_read_tools(["list_files", "read_file", "unknown_tool"])
    with patch("secval.infrastructure.audit.api_audit_model.urlopen", return_value=response) as send:
        model.next_action([])

    body = json.loads(send.call_args.args[0].data)
    assert [tool["function"]["name"] for tool in body["tools"]] == [
        "list_files", "read_file"
    ]


def test_native_mode_omits_empty_tool_list():
    response = MagicMock()
    response.__enter__.return_value = response
    response.read.return_value = b'{"choices":[{"message":{"content":"{}"}}]}'
    model = AuditModel(
        "https://example.invalid", "secret", "test", tool_protocol="native"
    )
    model.set_available_read_tools([])
    with patch("secval.infrastructure.audit.api_audit_model.urlopen", return_value=response) as send:
        model.next_action([])

    body = json.loads(send.call_args.args[0].data)
    assert "tools" not in body
    assert "tool_choice" not in body
