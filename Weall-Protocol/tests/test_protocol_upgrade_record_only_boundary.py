from __future__ import annotations

from weall.runtime.apply.protocol import apply_protocol
from weall.runtime.tx_admission_types import TxEnvelope


def _env(tx_type: str, nonce: int, payload: dict) -> TxEnvelope:
    return TxEnvelope(tx_type=tx_type, signer="@system", nonce=nonce, payload=payload, sig="", system=True)


def test_protocol_upgrade_declare_records_but_does_not_auto_apply() -> None:
    state = {"height": 7}
    out = apply_protocol(
        state,
        _env(
            "PROTOCOL_UPGRADE_DECLARE",
            1,
            {
                "upgrade_id": "upgrade-1",
                "version": "2026.06-v1.5",
                "hash": "abc123",
                "auto_apply": True,
                "artifact_url": "https://example.invalid/release.tar.gz",
                "migration_steps": ["do-not-run"],
            },
        ),
    )

    boundary = out["record_only_boundary"]
    assert boundary["execution_model"] == "record_only_no_auto_apply"
    assert boundary["artifact_apply_enabled"] is False
    assert boundary["migration_execution_enabled"] is False
    assert set(boundary["requested_execution_fields_ignored"]) == {"auto_apply", "artifact_url", "migration_steps"}
    rec = state["protocol"]["upgrades"]["upgrade-1"]
    assert rec["status"] == "declared"
    assert rec["record_only_boundary"] == boundary


def test_protocol_upgrade_activate_records_active_boundary_without_execution() -> None:
    state = {"height": 12}
    apply_protocol(state, _env("PROTOCOL_UPGRADE_DECLARE", 1, {"upgrade_id": "upgrade-2", "version": "v2"}))
    out = apply_protocol(
        state,
        _env(
            "PROTOCOL_UPGRADE_ACTIVATE",
            2,
            {"upgrade_id": "upgrade-2", "rollback": True, "execute_migration": True, "restart_node": True},
        ),
    )

    boundary = out["record_only_boundary"]
    assert boundary["rollback_execution_enabled"] is False
    assert boundary["restart_or_process_control_enabled"] is False
    assert set(boundary["requested_execution_fields_ignored"]) == {"rollback", "execute_migration", "restart_node"}
    assert state["protocol"]["active"]["record_only_boundary"] == boundary
