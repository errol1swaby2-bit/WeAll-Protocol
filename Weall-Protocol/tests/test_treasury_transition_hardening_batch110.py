from __future__ import annotations

import pytest

from weall.runtime.apply.roles import RolesApplyError, apply_roles
from weall.runtime.apply.treasury import TreasuryApplyError, apply_treasury
from weall.runtime.tx_admission import TxEnvelope


def _env(tx_type: str, signer: str, nonce: int, payload: dict, *, system: bool = False) -> TxEnvelope:
    return TxEnvelope(
        tx_type=tx_type,
        signer=signer,
        nonce=nonce,
        payload=payload,
        sig="sig",
        system=system,
        parent=(f"p:{max(0, nonce - 1)}" if system else None),
    )


def _mk_state() -> dict:
    return {
        "chain_id": "test",
        "height": 10,
        "time": 1,
        "accounts": {
            "alice": {"nonce": 0, "poh_tier": 3, "banned": False, "locked": False, "reputation": 1.0},
            "bob": {"nonce": 0, "poh_tier": 3, "banned": False, "locked": False, "reputation": 1.0},
            "SYSTEM": {"nonce": 0, "poh_tier": 3, "banned": False, "locked": False, "reputation": 1.0},
        },
        "roles": {
            "emissaries": {"seated": ["alice", "bob"]},
            "treasuries_by_id": {
                "t1": {
                    "signers": ["alice", "bob"],
                    "threshold": 2,
                    "created_by": "SYSTEM",
                    "require_emissary_signers": True,
                }
            },
        },
        "params": {
            "economic_unlock_time": 0,
            "economics_enabled": True,
            "system_signer": "SYSTEM",
        },
        "treasury": {
            "spends": {
                "sp1": {
                    "spend_id": "sp1",
                    "treasury_id": "t1",
                    "status": "proposed",
                    "threshold": 2,
                    "allowed_signers": ["alice", "bob"],
                    "signatures": {"alice": {"at_nonce": 1}},
                    "earliest_execute_height": 1,
                    "payload": {"amount": 5},
                }
            }
        },
    }


def test_treasury_signers_set_rejects_while_spend_open_batch110() -> None:
    state = _mk_state()
    with pytest.raises(RolesApplyError) as exc:
        apply_roles(
            state,
            _env(
                "TREASURY_SIGNERS_SET",
                "alice",
                2,
                {"treasury_id": "t1", "signers": ["alice", "bob"], "threshold": 2},
            ),
        )
    assert exc.value.code == "forbidden"
    assert exc.value.reason == "treasury_spend_open"


def test_treasury_signers_set_allowed_after_spend_cancel_batch110() -> None:
    state = _mk_state()
    state["treasury"]["spends"]["sp1"]["status"] = "canceled"
    meta = apply_roles(
        state,
        _env(
            "TREASURY_SIGNERS_SET",
            "alice",
            2,
            {"treasury_id": "t1", "signers": ["alice", "bob"], "threshold": 2},
        ),
    )
    assert meta and meta["applied"] == "TREASURY_SIGNERS_SET"


def test_treasury_policy_set_rejects_while_spend_open_batch110() -> None:
    state = _mk_state()
    with pytest.raises(TreasuryApplyError) as exc:
        apply_treasury(
            state,
            _env(
                "TREASURY_POLICY_SET",
                "SYSTEM",
                3,
                {"policy": {"max_programs": 10}},
                system=True,
            ),
        )
    assert exc.value.code == "forbidden"
    assert exc.value.reason == "treasury_spend_open"


def test_treasury_policy_set_allowed_after_spend_execute_batch110() -> None:
    state = _mk_state()
    state["treasury"]["spends"]["sp1"]["status"] = "executed"
    meta = apply_treasury(
        state,
        _env(
            "TREASURY_POLICY_SET",
            "SYSTEM",
            4,
            {"policy": {"max_programs": 10}},
            system=True,
        ),
    )
    assert meta and meta["applied"] == "TREASURY_POLICY_SET"
