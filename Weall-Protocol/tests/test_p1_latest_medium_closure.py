from __future__ import annotations

import pytest

from weall.runtime.apply.economics import EconomicsApplyError, apply_economics
from weall.runtime.tx_admission_types import TxEnvelope


def _econ_state() -> dict:
    return {
        "time": 1_000,
        "params": {
            "genesis_time": 0,
            "economic_unlock_time": 1,
            "economics_enabled": True,
        },
        "accounts": {
            "alice": {
                "balance": 10,
                "poh_tier": 0,
                "nonce": 0,
                "banned": False,
                "locked": False,
            },
            "@fees": {
                "balance": 0,
                "poh_tier": 0,
                "nonce": 0,
                "banned": False,
                "locked": False,
            },
        },
    }


def test_a11_f001_positive_fee_requires_explicit_disposition() -> None:
    state = _econ_state()
    env = TxEnvelope(
        tx_type="FEE_PAY",
        signer="alice",
        nonce=1,
        system=False,
        payload={"amount": 3},
    )

    with pytest.raises(EconomicsApplyError, match="fee_destination_required") as caught:
        apply_economics(state, env)

    assert caught.value.reason == "fee_destination_required"
    assert state["accounts"]["alice"]["balance"] == 10
    assert state["accounts"]["@fees"]["balance"] == 0
    assert state.get("economics", {}).get("fee_payments", []) == []


def test_a11_f001_destination_fee_still_conserves_balances() -> None:
    state = _econ_state()
    env = TxEnvelope(
        tx_type="FEE_PAY",
        signer="alice",
        nonce=1,
        system=False,
        payload={"amount": 3, "to_account_id": "@fees"},
    )

    result = apply_economics(state, env)

    assert result == {"applied": "FEE_PAY", "from": "alice", "to": "@fees", "amount": 3}
    assert state["accounts"]["alice"]["balance"] == 7
    assert state["accounts"]["@fees"]["balance"] == 3
    assert state["accounts"]["alice"]["balance"] + state["accounts"]["@fees"]["balance"] == 10


def test_a11_f002_nonzero_transfer_fee_policy_fails_closed_until_enforced() -> None:
    state = _econ_state()
    env = TxEnvelope(
        tx_type="FEE_POLICY_SET",
        signer="SYSTEM",
        nonce=1,
        system=True,
        payload={"transfer_fee_int": 100},
    )

    with pytest.raises(EconomicsApplyError, match="transfer_fee_policy_not_enforced") as caught:
        apply_economics(state, env)

    assert caught.value.reason == "transfer_fee_policy_not_enforced"
    assert state.get("economics", {}).get("fee_policy", {}).get("transfer_fee_int", 0) == 0


def test_a11_f002_zero_transfer_fee_policy_remains_allowed() -> None:
    state = _econ_state()
    env = TxEnvelope(
        tx_type="FEE_POLICY_SET",
        signer="SYSTEM",
        nonce=1,
        system=True,
        payload={"transfer_fee_int": 0},
    )

    result = apply_economics(state, env)

    assert result["applied"] == "FEE_POLICY_SET"
    assert result["fee_policy"]["transfer_fee_int"] == 0
