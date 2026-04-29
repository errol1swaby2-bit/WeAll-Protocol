from __future__ import annotations

import os

import pytest

from weall.oracle_service.config import OracleServiceConfig
from weall.oracle_service.transports.mock import MockDevTransport
from weall.oracle_service.transports.stalwart_smtp import StalwartSMTPTransport


def test_mock_transport_does_not_require_cloudflare_env(monkeypatch: pytest.MonkeyPatch, tmp_path) -> None:
    for key in list(os.environ):
        if key.startswith("CLOUDFLARE") or key.startswith("CF_"):
            monkeypatch.delenv(key, raising=False)
    monkeypatch.setenv("WEALL_EMAIL_TRANSPORT", "mock")
    monkeypatch.setenv("WEALL_MOCK_EMAIL_OUTBOX", str(tmp_path / "outbox.jsonl"))

    cfg = OracleServiceConfig.from_env()
    transport = cfg.build_transport()

    assert isinstance(transport, MockDevTransport)
    transport.validate_config()


def test_stalwart_transport_is_selected_without_cloudflare_env(monkeypatch: pytest.MonkeyPatch) -> None:
    for key in list(os.environ):
        if key.startswith("CLOUDFLARE") or key.startswith("CF_"):
            monkeypatch.delenv(key, raising=False)
    monkeypatch.setenv("WEALL_EMAIL_TRANSPORT", "stalwart_smtp")
    monkeypatch.setenv("WEALL_SMTP_HOST", "stalwart")
    monkeypatch.setenv("WEALL_SMTP_PORT", "587")

    cfg = OracleServiceConfig.from_env()
    transport = cfg.build_transport()

    assert isinstance(transport, StalwartSMTPTransport)
    transport.validate_config()


def test_cloudflare_named_transport_is_not_registered(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("WEALL_EMAIL_TRANSPORT", "cloudflare_optional")
    monkeypatch.delenv("CLOUDFLARE_API_TOKEN", raising=False)
    monkeypatch.delenv("CLOUDFLARE_ACCOUNT_ID", raising=False)

    cfg = OracleServiceConfig.from_env()
    with pytest.raises(ValueError) as exc:
        cfg.build_transport()

    assert str(exc.value) == "unsupported_email_transport:cloudflare_optional"
