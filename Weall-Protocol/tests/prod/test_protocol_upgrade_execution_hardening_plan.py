from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

from weall.runtime.apply.protocol import apply_protocol
from weall.runtime.tx_admission_types import TxEnvelope

ROOT = Path(__file__).resolve().parents[2]


def _env(tx_type: str, nonce: int, payload: dict, *, parent: str | None = None) -> TxEnvelope:
    if parent is None:
        parent = "CONSTITUTION_UPGRADE_DECLARE" if tx_type == "CONSTITUTION_UPGRADE_ACTIVATE" else "GOV_EXECUTE"
        if tx_type == "PROTOCOL_UPGRADE_ACTIVATE":
            parent = "PROTOCOL_UPGRADE_DECLARE"
    return TxEnvelope(tx_type=tx_type, signer="@system", nonce=nonce, payload=payload, sig="", system=True, parent=parent)


def test_protocol_upgrade_execution_hardening_plan_artifact_is_fresh_and_open() -> None:
    proc = subprocess.run(
        [sys.executable, "scripts/gen_protocol_upgrade_execution_hardening_plan_v1_5.py", "--check"],
        cwd=str(ROOT),
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
    payload = json.loads((ROOT / "generated" / "protocol_upgrade_execution_hardening_plan_v1_5.json").read_text(encoding="utf-8"))
    assert payload["blocker"] == "AUD-618-P0-003"
    assert payload["blocker_status"] == "open_future_mainnet_hardening"
    assert payload["execution_enabled"] is False
    assert payload["automatic_protocol_upgrades_ready"] is False
    assert payload["claim_boundaries"]["automatic_protocol_upgrades"] is False
    assert payload["claim_boundaries"]["protocol_migrations"] is False
    assert payload["claim_boundaries"]["protocol_rollbacks"] is False
    assert "deterministic_migration_vectors_with_before_after_state_roots" in payload["future_required_evidence"]
    assert "multi_node_staged_rollout_transcript" in payload["future_required_evidence"]


def test_upgrade_execution_hardening_docs_and_template_preserve_non_claims() -> None:
    docs = [
        ROOT / "docs" / "testnet" / "UPGRADE_EXECUTION_HARDENING_PLAN.md",
        ROOT / "docs" / "proofs" / "protocol-upgrade-execution-hardening" / "2026-07-05" / "README.md",
    ]
    for path in docs:
        text = path.read_text(encoding="utf-8").lower()
        assert "aud-618-p0-003" in text
        assert "record-only" in text
        assert "automatic" in text
        assert "migration" in text
        assert "rollback" in text
        assert "public beta" in text
    template = json.loads((ROOT / "docs" / "proofs" / "protocol-upgrade-execution-hardening" / "2026-07-05" / "PLAN_TEMPLATE.json").read_text(encoding="utf-8"))
    assert template["template_only"] is True
    assert template["external_execution_evidence_attached"] is False
    assert template["current_record_only_boundary"]["software_apply_enabled"] is False
    assert template["current_record_only_boundary"]["migration_execution_enabled"] is False
    assert template["current_record_only_boundary"]["rollback_execution_enabled"] is False
    assert template["claim_boundaries"]["public_beta_ready"] is False


def test_protocol_upgrade_future_execution_fields_are_ignored_and_disabled() -> None:
    state = {"height": 100}
    declare = apply_protocol(
        state,
        _env(
            "PROTOCOL_UPGRADE_DECLARE",
            1,
            {
                "upgrade_id": "future-exec",
                "version": "v1.6.0",
                "signed_manifest": {"digest": "sha256:" + "1" * 64},
                "artifact_cid": "bafyfutureartifact",
                "compatibility_window": {"stage_after_height": 110, "activate_not_before_height": 150},
                "operator_approval_policy": {"explicit_operator_approval_required": True},
                "migration_vector_hash": "sha256:" + "2" * 64,
                "rollback_vector_hash": "sha256:" + "3" * 64,
                "staged_rollout_plan": ["leader", "follower", "observer"],
                "auto_apply": True,
                "fetch_artifact": True,
                "execute_migration": True,
                "execute_rollback": True,
                "restart_node": True,
            },
        ),
    )
    boundary = declare["record_only_boundary"]
    assert boundary["artifact_fetched"] is False
    assert boundary["software_applied"] is False
    assert boundary["migration_executed"] is False
    assert boundary["rollback_execution_enabled"] is False
    assert boundary["restart_or_process_control_enabled"] is False
    assert boundary["automatic_upgrade_supported"] is False
    for key in ("signed_manifest", "artifact_cid", "migration_vector_hash", "rollback_vector_hash", "execute_rollback", "restart_node"):
        assert key in boundary["requested_execution_fields_ignored"]

    activate = apply_protocol(
        state,
        _env(
            "PROTOCOL_UPGRADE_ACTIVATE",
            2,
            {
                "upgrade_id": "future-exec",
                "version": "v1.6.0",
                "activation_height": 160,
                "execute_migration": True,
                "rollback": True,
                "restart_node": True,
            },
        ),
    )
    active_boundary = activate["record_only_boundary"]
    assert active_boundary["migration_execution_enabled"] is False
    assert active_boundary["rollback_execution_enabled"] is False
    assert active_boundary["restart_or_process_control_enabled"] is False
    assert state["protocol"]["active"]["software_applied"] is False
    assert state["protocol"]["active"]["migration_executed"] is False
    assert state["protocol"]["active"]["rollback_available"] is False


def test_constitution_upgrade_future_execution_fields_are_ignored_and_disabled() -> None:
    state = {"height": 200}
    declare = apply_protocol(
        state,
        _env(
            "CONSTITUTION_UPGRADE_DECLARE",
            1,
            {
                "constitution_id": "const-future",
                "constitution_version": "v0.3",
                "document_hash": "sha256:" + "a" * 64,
                "traceability_hash": "sha256:" + "b" * 64,
                "fetch_document": True,
                "apply_document": True,
                "execute_migration": True,
                "rollback": True,
                "restart_node": True,
                "auto_apply": True,
            },
        ),
    )
    boundary = declare["record_only_boundary"]
    assert boundary["document_fetched"] is False
    assert boundary["artifact_fetched"] is False
    assert boundary["document_apply_enabled"] is False
    assert boundary["migration_execution_enabled"] is False
    assert boundary["rollback_execution_enabled"] is False
    assert boundary["restart_or_process_control_enabled"] is False
    for key in ("fetch_document", "apply_document", "execute_migration", "rollback", "restart_node", "auto_apply"):
        assert key in boundary["requested_execution_fields_ignored"]

    activate = apply_protocol(
        state,
        _env(
            "CONSTITUTION_UPGRADE_ACTIVATE",
            2,
            {
                "constitution_id": "const-future",
                "activation_height": 260,
                "execute_migration": True,
                "execute_rollback": True,
                "restart_node": True,
            },
        ),
    )
    active_boundary = activate["record_only_boundary"]
    assert active_boundary["software_applied"] is False
    assert active_boundary["migration_executed"] is False
    assert active_boundary["rollback_execution_enabled"] is False
    assert active_boundary["restart_or_process_control_enabled"] is False
