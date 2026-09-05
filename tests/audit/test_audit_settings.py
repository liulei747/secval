"""请求等待时长可配置，但不是整个任务的硬性截止时间。"""

from unittest.mock import MagicMock, patch

import pytest

from secval.config.audit_settings import load_audit_settings
from secval.infrastructure.audit.api_audit_model import AuditModel


def test_timeout_setting(monkeypatch):
    monkeypatch.setenv("SECVAL_AUDIT_TIMEOUT_SECONDS", "180")
    assert load_audit_settings().timeout_seconds == 180


def test_output_budget_setting(monkeypatch):
    monkeypatch.setenv("SECVAL_AUDIT_MAX_OUTPUT_TOKENS", "12000")
    assert load_audit_settings().max_output_tokens == 12000


@pytest.mark.parametrize("value,expected", [("", None), ("enabled", "enabled"), ("disabled", "disabled")])
def test_thinking_configuration_is_opt_in(monkeypatch, value, expected):
    monkeypatch.setenv("SECVAL_AUDIT_THINKING", value)
    assert load_audit_settings().thinking == expected


def test_invalid_thinking_configuration(monkeypatch):
    monkeypatch.setenv("SECVAL_AUDIT_THINKING", "guess")
    with pytest.raises(ValueError):
        load_audit_settings()


@pytest.mark.parametrize("value", [True, 255, 32769, "8192"])
def test_invalid_output_budget(value):
    with pytest.raises(ValueError):
        AuditModel("https://example.invalid", "test", "test", max_output_tokens=value)


def test_output_budget_reaches_request():
    import json

    response = MagicMock()
    response.__enter__.return_value = response
    response.read.return_value = b'{"choices":[{"message":{"content":"{}"}}]}'
    with patch("secval.infrastructure.audit.api_audit_model.urlopen", return_value=response) as send:
        AuditModel("https://example.invalid", "test", "test", max_output_tokens=12000).next_action([])
    assert json.loads(send.call_args.args[0].data)["max_tokens"] == 12000


@pytest.mark.parametrize("value", ["0", "601", "invalid"])
def test_invalid_timeout_setting(monkeypatch, value):
    monkeypatch.setenv("SECVAL_AUDIT_TIMEOUT_SECONDS", value)
    with pytest.raises(ValueError):
        load_audit_settings()


def test_timeout_reaches_transport():
    response = MagicMock()
    response.__enter__.return_value = response
    response.read.return_value = b'{"choices":[{"message":{"content":"{}"}}]}'
    with patch("secval.infrastructure.audit.api_audit_model.urlopen", return_value=response) as send:
        AuditModel("https://example.invalid", "test", "test", timeout_seconds=180).next_action([])
    assert send.call_args.kwargs["timeout"] == 180


@pytest.mark.parametrize("value", [True, 0, 601, "120"])
def test_model_rejects_invalid_timeout(value):
    with pytest.raises(ValueError):
        AuditModel("https://example.invalid", "test", "test", timeout_seconds=value)
