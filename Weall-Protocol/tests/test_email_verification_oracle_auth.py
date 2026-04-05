from __future__ import annotations

from weall.poh import email_verification as mod
from weall.poh.email_verification import EmailVerificationService, OracleCallerIdentity


def test_begin_sends_signed_headers_and_operator_account(monkeypatch) -> None:
    captured: dict[str, object] = {}

    def fake_post_json(
        url: str,
        payload: dict[str, object],
        *,
        timeout_s: int = 10,
        headers: dict[str, str] | None = None,
    ):
        captured["url"] = url
        captured["payload"] = dict(payload)
        captured["headers"] = dict(headers or {})
        return {"challenge_id": "challenge-123", "expires_at_ms": mod._now_ms() + 60_000}

    monkeypatch.setattr(mod, "_post_json", fake_post_json)

    svc = EmailVerificationService(
        ttl_ms=300_000,
        secret="local-secret",
        email_verify_base_url="https://oracle.example",
        caller_identity=OracleCallerIdentity(
            operator_account="@genesis",
            node_pubkey="11" * 32,
            node_privkey="22" * 32,
        ),
    )

    result = svc.begin(account="@alice", email="Alice@example.com")
    assert result["request_id"] == "challenge-123"
    assert int(result["expires_ms"]) > 0
    assert captured["url"] == "https://oracle.example/start"
    assert captured["payload"] == {
        "account_id": "@alice",
        "email": "alice@example.com",
        "operator_account_id": "@genesis",
    }
    headers = captured["headers"]
    assert isinstance(headers, dict)
    assert headers["x-weall-oracle-account"] == "@genesis"
    assert headers["x-weall-oracle-pubkey"] == "11" * 32
    assert headers["x-weall-oracle-signature"]
    assert headers["x-weall-oracle-body-sha256"]
