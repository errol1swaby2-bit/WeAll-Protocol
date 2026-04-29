from __future__ import annotations

import json
import os
import re
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from weall.api.routes_public_parts import poh as poh_routes
from weall.api.errors import ApiError
from weall.oracle_service.transports.base import EmailMessage, EmailSendResult
from weall.poh.email_verification import EmailVerificationService, OracleCallerIdentity, OracleRequestError

ROOT = Path(__file__).resolve().parents[1]


class CapturingTransport:
    provider = "capture"

    def __init__(self) -> None:
        self.messages: list[EmailMessage] = []

    def validate_config(self) -> None:
        return None

    def send(self, message: EmailMessage) -> EmailSendResult:
        self.messages.append(message)
        return EmailSendResult(provider=self.provider, message_id="msg-1")


class FailingTransport:
    provider = "failing"

    def validate_config(self) -> None:
        return None

    def send(self, message: EmailMessage) -> EmailSendResult:
        raise RuntimeError("smtp_unavailable")


def _caller() -> OracleCallerIdentity:
    return OracleCallerIdentity(operator_account="oracle:poh-email:test", node_pubkey="11" * 32, node_privkey="22" * 32)


def _extract_code(body: str) -> str:
    match = re.search(r"Your verification code:\n([0-9]{6})", body)
    assert match, body
    return match.group(1)


def test_email_verification_complete_does_not_return_relay_token(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv("WEALL_POH_EMAIL_CHALLENGE_STORE", str(tmp_path / "challenges.json"))
    transport = CapturingTransport()
    svc = EmailVerificationService(
        ttl_ms=300_000,
        secret="local-secret",
        official_sender="verify@poh.weall.example",
        transport=transport,
        caller_identity=_caller(),
    )

    started = svc.begin(account="@alice", email="alice@example.org", chain_id="weall-test")
    code = _extract_code(transport.messages[0].body_text)
    completed = svc.complete(
        account="@alice",
        email="alice@example.org",
        code=code,
        request_id=started["request_id"],
        chain_id="weall-test",
    )

    assert completed["ok"] is True
    assert completed["completed"] is True
    assert "relay_token" not in completed


def test_dev_code_exposure_is_forbidden_in_production(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv("WEALL_MODE", "prod")
    monkeypatch.setenv("WEALL_POH_EMAIL_EXPOSE_DEV_CODE", "1")
    monkeypatch.setenv("WEALL_POH_EMAIL_CHALLENGE_STORE", str(tmp_path / "challenges.json"))
    svc = EmailVerificationService(
        ttl_ms=300_000,
        secret="local-secret",
        official_sender="verify@poh.weall.example",
        transport=CapturingTransport(),
        caller_identity=_caller(),
    )

    with pytest.raises(OracleRequestError) as exc:
        svc.begin(account="@alice", email="alice@example.org", chain_id="weall-test")
    assert str(exc.value) == "dev_code_exposure_forbidden_in_prod"
    assert not (tmp_path / "challenges.json").exists()


def test_transport_failure_does_not_persist_successful_challenge(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    store = tmp_path / "challenges.json"
    monkeypatch.setenv("WEALL_POH_EMAIL_CHALLENGE_STORE", str(store))
    svc = EmailVerificationService(
        ttl_ms=300_000,
        secret="local-secret",
        official_sender="verify@poh.weall.example",
        transport=FailingTransport(),
        caller_identity=_caller(),
    )

    with pytest.raises(RuntimeError, match="smtp_unavailable"):
        svc.begin(account="@alice", email="alice@example.org", chain_id="weall-test")
    assert not store.exists()


def test_production_inprocess_email_oracle_requires_dedicated_signing_key(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("WEALL_MODE", "prod")
    monkeypatch.setenv("WEALL_EMAIL_ORACLE_ID", "oracle:poh-email:test")
    monkeypatch.setenv("WEALL_POH_EMAIL_HASH_SALT", "test-salt")
    monkeypatch.delenv("WEALL_EMAIL_ORACLE_PRIVATE_KEY", raising=False)
    monkeypatch.delenv("WEALL_EMAIL_ORACLE_PRIVATE_KEY_FILE", raising=False)

    class DummyService:
        caller_identity = _caller()

    with pytest.raises(ApiError) as exc:
        poh_routes._sign_email_control_attestation(
            svc=DummyService(),
            chain_id="weall-test",
            account="@alice",
            email="alice@example.org",
            challenge_id="challenge:1",
            current_height=1,
        )
    assert exc.value.code == "missing_email_oracle_private_key"


def test_standalone_oracle_healthz_exposes_non_secret_chain_anchors(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    manifest = {
        "chain_id": "weall-test",
        "genesis_hash": "genesis-hash",
        "tx_index_hash": "tx-index-hash",
        "oracle": {"expected_profile": "test"},
    }
    manifest_path = tmp_path / "manifest.json"
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    monkeypatch.setenv("WEALL_CHAIN_MANIFEST_PATH", str(manifest_path))
    monkeypatch.setenv("WEALL_EMAIL_TRANSPORT", "mock")

    from weall.oracle_service.__main__ import app

    response = TestClient(app).get("/healthz")
    assert response.status_code == 200
    body = response.json()
    assert body["ok"] is True
    assert body["profile"] == "test"
    assert body["chain_id"] == "weall-test"
    assert body["expected_genesis_hash"] == "genesis-hash"
    assert body["expected_tx_index_hash"] == "tx-index-hash"
    assert "private" not in json.dumps(body).lower()
    assert "secret" not in json.dumps(body).lower()


def test_old_email_oracle_aliases_and_relay_symbols_are_absent_from_source() -> None:
    checked_paths = [
        ROOT / "src" / "weall" / "poh" / "email_verification.py",
        ROOT / "src" / "weall" / "oracle_service" / "config.py",
        ROOT / "src" / "weall" / "api" / "routes_public_parts" / "poh.py",
        ROOT / "scripts" / "prod_oracle_env_check.sh",
        ROOT / "scripts" / "prod_oracle_smoke.sh",
        ROOT / "scripts" / "demo_oracle_smoke.sh",
        ROOT / "scripts" / "demo_full_oracle_preflight.sh",
        ROOT / "scripts" / "build_node_operator_onboarding_bundle.py",
    ]
    forbidden = [
        "WEALL_EMAIL_HOST",
        "WEALL_EMAIL_PORT",
        "WEALL_EMAIL_USER",
        "WEALL_EMAIL_PASS",
        "WEALL_EMAIL_FROM",
        "WEALL_EMAIL_ORACLE_URL",
        "WEALL_POH_EMAIL_SECRET",
        "WEALL_POH_EMAIL_TTL_MS",
        "RelayCompletionToken",
        "relay_token",
        "begin_legacy",
        "verify_legacy",
        "email_verify_base_url",
    ]
    for path in checked_paths:
        body = path.read_text(encoding="utf-8")
        for token in forbidden:
            assert token not in body, f"{token} should not remain in {path.relative_to(ROOT)}"

    assert not (ROOT / "src" / "weall" / "email" / "smtp_sender.py").exists()
    assert not (ROOT / "src" / "weall" / "poh" / "email_service.py").exists()
