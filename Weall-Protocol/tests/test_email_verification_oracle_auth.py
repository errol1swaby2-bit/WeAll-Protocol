from __future__ import annotations

from pathlib import Path

from weall.oracle_service.transports.base import EmailMessage, EmailSendResult
from weall.poh.email_verification import EmailVerificationService, OracleCallerIdentity


class CapturingTransport:
    provider = "capture"

    def __init__(self) -> None:
        self.messages: list[EmailMessage] = []

    def validate_config(self) -> None:
        return None

    def send(self, message: EmailMessage) -> EmailSendResult:
        self.messages.append(message)
        return EmailSendResult(provider=self.provider, message_id="msg-1")


def test_begin_uses_injected_provider_neutral_transport(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setenv("WEALL_POH_EMAIL_CHALLENGE_STORE", str(tmp_path / "challenges.json"))
    monkeypatch.setenv("WEALL_POH_EMAIL_HASH_SALT", "local-secret")

    transport = CapturingTransport()
    svc = EmailVerificationService(
        ttl_ms=300_000,
        secret="local-secret",
        official_sender="verify@poh.weall.example",
        transport=transport,
        caller_identity=OracleCallerIdentity(
            operator_account="oracle:poh-email:test",
            node_pubkey="11" * 32,
            node_privkey="22" * 32,
        ),
    )

    result = svc.begin(account="@alice", email="Alice@example.com", chain_id="weall-test")

    assert result["ok"] is True
    assert result["request_id"].startswith("poh_email_")
    assert result["provider"] == "capture"
    assert result["official_sender"] == "verify@poh.weall.example"
    assert len(transport.messages) == 1
    msg = transport.messages[0]
    assert msg.to_email == "alice@example.com"
    assert msg.from_email == "verify@poh.weall.example"
    assert result["security_phrase"] in msg.body_text
    assert "Your verification code:" in msg.body_text
