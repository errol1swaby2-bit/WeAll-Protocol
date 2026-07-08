from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _read(rel: str) -> str:
    return (ROOT / rel).read_text(encoding="utf-8")


def test_boot_node_operator_requires_backend_promotion_status_and_baseline_active() -> None:
    src = _read("scripts/boot_node_operator.sh")
    assert "operator-promotion-status" in src
    assert "service_reboot_allowed" in src
    assert "node_operator_active" in src
    assert "node_key_registered" in src
    assert "WEALL_NODE_PRIVKEY_FILE" in src
    assert "Service mode does not imply validator authority" in src
    assert "WEALL_BFT_ENABLED=\"${WEALL_BFT_ENABLED:-0}\"" in src
    assert "WEALL_VALIDATOR_SIGNING_ENABLED=\"${WEALL_VALIDATOR_SIGNING_ENABLED:-0}\"" in src


def test_promoted_validator_reboot_fails_until_validator_authority_active() -> None:
    preflight = _read("scripts/promoted_validator_preflight.sh")
    reboot = _read("scripts/reboot_promoted_observer_as_validator.sh")
    live_gate = _read("scripts/promoted_validator_live_gate.sh")
    combined = preflight + reboot + live_gate
    assert "operator-promotion-status" in combined
    assert "validator_reboot_allowed" in combined
    assert "validator_active" in combined
    assert "validator_authority_not_active" in combined
    assert "WEALL_NODE_PRIVKEY_FILE is required" in reboot
    assert "inline node private keys are refused" in reboot
    assert "validator authority is active" in reboot.lower()
