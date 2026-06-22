from __future__ import annotations

import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_external_observer_live_gate_script_contract_batch341() -> None:
    script_path = ROOT / "scripts" / "external_observer_live_gate.sh"
    script = script_path.read_text(encoding="utf-8")

    subprocess.run(["bash", "-n", str(script_path)], check=True)

    assert "external observer live gate requires a remote non-local genesis API base" in script
    assert "http://127.0.0.1*" in script
    assert "http://localhost*" in script
    assert "https://127.0.0.1*" in script
    assert "https://localhost*" in script

    assert 'export WEALL_OBSERVER_MODE="1"' in script
    assert 'export WEALL_VALIDATOR_SIGNING_ENABLED="0"' in script
    assert 'export WEALL_BFT_ENABLED="0"' in script
    assert 'export WEALL_HELPER_MODE_ENABLED="0"' in script
    assert 'export WEALL_BLOCK_LOOP_AUTOSTART="0"' in script

    assert "WEALL_AUTHORITY_SIGNER_PRIVKEY" in script
    assert "WEALL_AUTHORITY_PRIVKEY" in script
    assert "WEALL_ORACLE_AUTHORITY_SIGNER_PRIVKEY" in script
    assert "WEALL_ORACLE_AUTHORITY_PRIVKEY" in script
    assert "WEALL_NAMED_HOSTING_PROVIDER_API_TOKEN" in script
    assert 'SMTP_SECRET_VAR="WEALL_SM""TP_PASSWORD"' in script

    assert "SigningKey.generate()" in script
    assert "ACCOUNT_REGISTER" in script
    assert "ACCOUNT_DEVICE_REGISTER node key binding" in script
    assert "ACCOUNT_DEVICE_REGISTER" in script
    assert "PEER_ADVERTISE" in script
    assert "PEER_REQUEST_CONNECT" in script
    assert "POH_ASYNC_REQUEST_OPEN" in script
    assert "POH_ASYNC_EVIDENCE_DECLARE" in script
    assert "POH_ASYNC_EVIDENCE_BIND" in script
    assert "/v1/accounts/" in script
    assert "/v1/poh/async/case/" in script
    assert "observer_account_unexpected_validator_authority" in script
    assert "OK: trusted external observer live gate passed" in script
    assert 'KEEP_WORK_DIR="${WEALL_EXTERNAL_OBSERVER_KEEP_WORK_DIR:-0}"' in script
    assert "WARNING: retained files include private observer account/node keys" in script


def test_first_external_observer_runbook_contract_batch341() -> None:
    doc = (ROOT / "docs" / "FIRST_EXTERNAL_OBSERVER_TEST.md").read_text(encoding="utf-8")

    assert "Trusted External Observer" in doc
    assert "bash scripts/external_observer_live_gate.sh" in doc
    assert "WEALL_GENESIS_API_BASE" in doc
    assert "must not be localhost" in doc.lower() or "non-local" in doc.lower()
    assert "ACCOUNT_REGISTER" in doc
    assert "ACCOUNT_DEVICE_REGISTER" in doc
    assert "PEER_ADVERTISE" in doc
    assert "PEER_REQUEST_CONNECT" in doc
    assert "POH_ASYNC_REQUEST_OPEN" in doc
    assert "POH_ASYNC_EVIDENCE_DECLARE" in doc
    assert "POH_ASYNC_EVIDENCE_BIND" in doc
    assert "observer-only" in doc.lower() or "observer only" in doc.lower()
    assert "genesis private keys" in doc or "genesis authority key material" in doc
    assert "named hosting-provider" in doc
    assert "SMTP" in doc
    assert "DNS" in doc
    assert "OK: trusted external observer live gate passed" in doc
    assert "case creation and evidence binding only" in doc
    assert "WEALL_EXTERNAL_OBSERVER_KEEP_WORK_DIR=1" in doc
