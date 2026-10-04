from __future__ import annotations

import pytest

from weall.runtime.apply.governance import _apply_gov_proposal_create
from weall.runtime.apply.protocol import ProtocolApplyError, apply_protocol
from weall.runtime.errors import ApplyError
from weall.runtime.tx_admission_types import TxEnvelope

DOC_HASH = "sha256:" + "a" * 64
TRACE_HASH = "sha256:" + "b" * 64
RIGHTS_HASH = "sha256:" + "c" * 64


def _strict_state() -> dict:
    return {
        "chain_id": "weall-prod",
        "height": 100,
        "accounts": {
            "@alice": {"poh_tier": 2},
            "@bob": {"poh_tier": 2},
        },
    }


def _constitution_action(tx_type: str) -> dict:
    if tx_type == "CONSTITUTION_UPGRADE_DECLARE":
        payload = {
            "constitution_id": "const-v0-2",
            "constitution_version": "v0.2",
            "document_hash": DOC_HASH,
            "traceability_hash": TRACE_HASH,
            "rights_floor_hash": RIGHTS_HASH,
        }
    else:
        payload = {
            "constitution_id": "const-v0-2",
            "constitution_version": "v0.2",
            "document_hash": DOC_HASH,
            "traceability_hash": TRACE_HASH,
            "activation_height": 200,
        }
    return {"tx_type": tx_type, "payload": payload}


def test_strict_governance_cannot_author_constitution_upgrade_actions() -> None:
    state = _strict_state()
    for tx_type in ("CONSTITUTION_UPGRADE_DECLARE", "CONSTITUTION_UPGRADE_ACTIVATE"):
        env = TxEnvelope(
            tx_type="GOV_PROPOSAL_CREATE",
            signer="@alice",
            nonce=1,
            payload={
                "proposal_id": f"constitutional-{tx_type.lower()}",
                "title": "Constitution amendment attempt",
                "rules": {"start_stage": "draft"},
                "actions": [_constitution_action(tx_type)],
            },
            chain_id="weall-prod",
        )
        with pytest.raises(ApplyError) as exc_info:
            _apply_gov_proposal_create(state, env)
        assert exc_info.value.code == "forbidden"
        assert exc_info.value.reason == "constitutional_amendment_process_not_enabled"


def test_strict_protocol_apply_rejects_direct_system_constitution_mutation() -> None:
    state = _strict_state()
    env = TxEnvelope(
        tx_type="CONSTITUTION_UPGRADE_DECLARE",
        signer="SYSTEM",
        nonce=1,
        payload=_constitution_action("CONSTITUTION_UPGRADE_DECLARE")["payload"],
        sig="",
        system=True,
        parent="gov:proposal:approved",
        chain_id="weall-prod",
    )
    with pytest.raises(ProtocolApplyError) as exc_info:
        apply_protocol(state, env)
    assert exc_info.value.code == "forbidden"
    assert exc_info.value.reason == (
        "constitutional_activation_scope_disabled_pending_normative_process"
    )
    assert state.get("constitution") is None


def test_non_strict_record_only_compatibility_remains_non_authoritative() -> None:
    state = {"height": 10, "params": {"mode": "dev"}}
    env = TxEnvelope(
        tx_type="CONSTITUTION_UPGRADE_DECLARE",
        signer="SYSTEM",
        nonce=1,
        payload=_constitution_action("CONSTITUTION_UPGRADE_DECLARE")["payload"],
        sig="",
        system=True,
        parent="GOV_EXECUTE",
    )
    out = apply_protocol(state, env)
    assert out is not None
    assert out["applied"] == "CONSTITUTION_UPGRADE_DECLARE"
    rec = state["constitution"]["upgrades"]["const-v0-2"]
    assert rec["record_only_boundary"]["automatic_constitution_apply_supported"] is False
    assert rec["record_only_boundary"]["operator_action_required"] is True
