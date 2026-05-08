from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_external_observer_smoke_script_forces_observer_safety_batch313() -> None:
    script = (ROOT / "scripts" / "external_observer_onboarding_smoke.sh").read_text(encoding="utf-8")
    assert 'WEALL_NODE_LIFECYCLE_STATE="observer_onboarding"' in script
    assert 'WEALL_OBSERVER_MODE="1"' in script
    assert 'WEALL_VALIDATOR_SIGNING_ENABLED="0"' in script
    assert 'WEALL_BFT_ENABLED="0"' in script
    assert 'WEALL_HELPER_MODE_ENABLED="0"' in script
    assert 'WEALL_BLOCK_LOOP_AUTOSTART="0"' in script
    assert "verify_node_operator_onboarding_bundle.py" in script
    assert "prod_chain_manifest_check.sh" in script
    assert "/v1/chain/identity" in script
    assert "WEALL_CLOUDFLARE_API_TOKEN" in script
    assert "WEALL_SMTP_PASSWORD" in script


def test_external_observer_runbook_documents_no_external_identity_authority_batch313() -> None:
    doc = (ROOT / "docs" / "TRUSTED_EXTERNAL_OBSERVER_TESTER_RUNBOOK.md").read_text(encoding="utf-8")
    assert "observer-first" in doc
    assert "cannot propose blocks" in doc
    assert "cannot" in doc and "sign validator messages" in doc
    assert "ACCOUNT_REGISTER" in doc
    assert "PEER_ADVERTISE" in doc
    assert "POH_ASYNC_REQUEST_OPEN" in doc
    assert "ROLE_NODE_OPERATOR_ENROLL" in doc
    assert "no email, Cloudflare, SMTP, DNS, OAuth, CAPTCHA, KYC" in doc
