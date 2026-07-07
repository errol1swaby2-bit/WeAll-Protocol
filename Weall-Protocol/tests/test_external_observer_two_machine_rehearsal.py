from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_two_machine_rehearsal_script_forces_remote_observer_safety() -> None:
    script = (ROOT / "scripts" / "rehearse_external_observer_two_machine.sh").read_text(encoding="utf-8")
    assert "WEALL_GENESIS_API_BASE" in script
    assert "two-machine rehearsal requires a remote genesis API base" in script
    assert "http://127.0.0.1" in script
    assert 'WEALL_NODE_LIFECYCLE_STATE="observer_onboarding"' in script
    assert 'WEALL_OBSERVER_MODE="1"' in script
    assert 'WEALL_VALIDATOR_SIGNING_ENABLED="0"' in script
    assert 'WEALL_BFT_ENABLED="0"' in script
    assert 'WEALL_HELPER_MODE_ENABLED="0"' in script
    assert 'WEALL_BLOCK_LOOP_AUTOSTART="0"' in script
    assert "external_observer_onboarding_smoke.sh" in script
    assert "/v1/health" in script
    assert "/v1/ready" in script
    assert "/v1/chain/identity" in script
    assert "/v1/net/relay/status" in script
    assert "require_recipient_pubkey" in script
    assert "allow_unbound_recipient_fetch" in script
    assert "transport_only" in script
    assert "WEALL_NAMED_HOSTING_PROVIDER_API_TOKEN" in script
    assert 'SMTP_SECRET_VAR="WEALL_SM""TP_PASSWORD"' in script
