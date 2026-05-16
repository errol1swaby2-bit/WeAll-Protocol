from __future__ import annotations

import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _read(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")


def test_promoted_validator_scripts_are_syntax_checked_batch346() -> None:
    scripts = [
        "scripts/promoted_validator_preflight.sh",
        "scripts/reboot_promoted_observer_as_validator.sh",
        "scripts/promoted_validator_live_gate.sh",
        "scripts/external_observer_to_validator_live_gate.sh",
    ]
    for script in scripts:
        subprocess.run(["bash", "-n", str(ROOT / script)], check=True)


def test_reboot_script_clears_observer_posture_before_enabling_validator_batch346() -> None:
    text = _read("scripts/reboot_promoted_observer_as_validator.sh")
    assert "unset WEALL_NODE_OPERATOR_ONBOARDING_BUNDLE" in text
    assert 'WEALL_NODE_LIFECYCLE_STATE="production_service"' in text
    assert 'WEALL_OBSERVER_MODE="0"' in text
    assert 'WEALL_BFT_ENABLED="1"' in text
    assert 'WEALL_VALIDATOR_SIGNING_ENABLED="1"' in text
    assert "scripts/promoted_validator_preflight.sh" in text
    assert "scripts/prod_node_preflight.sh" in text
    assert "scripts/run_node_prod.sh" in text


def test_promoted_validator_preflight_checks_protocol_authority_and_chain_identity_batch346() -> None:
    text = _read("scripts/promoted_validator_preflight.sh")
    assert "/v1/chain/identity" in text
    assert "/v1/accounts/" in text and "/operator-status" in text
    assert "/v1/status/consensus" in text
    assert "baseline_node_operator_not_active" in text
    assert "validator_responsibility_not_active" in text
    assert "active_validator_count_below_required" in text
    assert "tx_index_hash_mismatch" in text
    assert "validator_readiness_{key}_mismatch" in text
    assert "runtime_profile_hash" in text
    assert "readiness_receipt_hash_missing" in text
    assert "observer mode must be cleared" in text


def test_post_boot_live_gate_requires_effective_local_validator_batch346() -> None:
    text = _read("scripts/promoted_validator_live_gate.sh")
    assert "local_validator_authority_not_effective" in text
    assert "local_signing_not_allowed_by_consensus_state" in text
    assert "local_is_not_active_validator" in text
    assert "chain_id_mismatch" in text
    assert "tx_index_hash_mismatch" in text


def test_observer_to_validator_gate_does_not_synthesize_system_authority_batch346() -> None:
    text = _read("scripts/external_observer_to_validator_live_gate.sh")
    assert "external_observer_live_gate.sh" in text
    assert "ROLE_NODE_OPERATOR_ACTIVATE is committed by system/governance authority" in text
    assert "VALIDATOR_READINESS_VERIFY is committed by system authority" in text
    assert "ROLE_VALIDATOR_ACTIVATE and validator-set update are committed" in text
    assert "promoted_validator_preflight.sh" in text


def test_promoted_validator_docs_do_not_overclaim_batch346() -> None:
    text = _read("docs/PROMOTED_OBSERVER_TO_VALIDATOR_RUNBOOK.md")
    assert "Observer onboarding proves account/device/peer/PoH-case creation" in text
    assert "It does not prove node-operator authority" in text
    assert "promoted_validator_preflight.sh" in text
    assert "promoted_validator_live_gate.sh" in text
    assert "This script does not create system/governance authority by itself" in text
    assert "State sync / catchup boundary before signing" in text
    assert "remote genesis authority as local signing authority" in text
