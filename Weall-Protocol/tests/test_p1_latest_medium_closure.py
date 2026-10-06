from __future__ import annotations

import pytest

from weall.runtime.apply.economics import EconomicsApplyError, apply_economics
from weall.runtime.tx_admission_types import TxEnvelope


def _econ_state(*, balance: int = 10, fee_sink: bool = False) -> dict:
    params = {
        "genesis_time": 0,
        "economic_unlock_time": 1,
        "economics_enabled": True,
    }
    if fee_sink:
        params["fee_sink_account"] = "@fees"
    return {
        "time": 1_000,
        "params": params,
        "accounts": {
            "alice": {
                "balance": balance,
                "poh_tier": 0,
                "nonce": 0,
                "banned": False,
                "locked": False,
            },
            "bob": {
                "balance": 0,
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


def _fee_policy(amount: int) -> TxEnvelope:
    return TxEnvelope(
        tx_type="FEE_POLICY_SET",
        signer="SYSTEM",
        nonce=1,
        system=True,
        payload={"transfer_fee_int": amount},
    )


def _transfer(*, amount: int = 20, nonce: int = 2) -> TxEnvelope:
    return TxEnvelope(
        tx_type="BALANCE_TRANSFER",
        signer="alice",
        nonce=nonce,
        system=False,
        payload={"to_account_id": "bob", "amount": amount},
    )


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


def test_a11_f002_nonzero_transfer_fee_is_atomically_settled_and_deduped() -> None:
    state = _econ_state(balance=100, fee_sink=True)

    policy = apply_economics(state, _fee_policy(7))
    assert policy["fee_policy"]["transfer_fee_int"] == 7

    # A standalone zero/wrongly-bound fee record is not an authorization path
    # for the charged transfer and therefore cannot bypass atomic settlement.
    fake_payment = TxEnvelope(
        tx_type="FEE_PAY",
        signer="alice",
        nonce=9,
        system=False,
        payload={
            "tx_id": "wrong-transfer",
            "tx_type": "BALANCE_TRANSFER",
            "amount": 0,
            "to_account_id": "@fees",
        },
    )
    apply_economics(state, fake_payment)

    env = _transfer()
    result = apply_economics(state, env)

    assert result["applied"] == "BALANCE_TRANSFER"
    assert result["amount"] == 20
    assert result["fee_amount"] == 7
    assert result["fee_to"] == "@fees"
    assert state["accounts"]["alice"]["balance"] == 73
    assert state["accounts"]["bob"]["balance"] == 20
    assert state["accounts"]["@fees"]["balance"] == 7

    settlements = [
        row for row in state["economics"]["fee_payments"] if row.get("tx_id") == "transfer:alice:2"
    ]
    assert settlements == [
        {
            "at_nonce": 2,
            "from": "alice",
            "to": "@fees",
            "amount": 7,
            "tx_id": "transfer:alice:2",
            "tx_type": "BALANCE_TRANSFER",
            "payload": {
                "settlement": "atomic_balance_transfer",
                "transfer_id": "transfer:alice:2",
            },
            "parent": None,
        }
    ]

    before = (
        state["accounts"]["alice"]["balance"],
        state["accounts"]["bob"]["balance"],
        state["accounts"]["@fees"]["balance"],
        len(state["economics"]["fee_payments"]),
    )
    replay = apply_economics(state, env)
    after = (
        state["accounts"]["alice"]["balance"],
        state["accounts"]["bob"]["balance"],
        state["accounts"]["@fees"]["balance"],
        len(state["economics"]["fee_payments"]),
    )
    assert replay["deduped"] is True
    assert replay["fee_amount"] == 7
    assert before == after


def test_a11_f002_positive_fee_transfer_fails_without_canonical_sink() -> None:
    state = _econ_state(balance=100)
    apply_economics(state, _fee_policy(7))

    with pytest.raises(EconomicsApplyError, match="fee_destination_required") as caught:
        apply_economics(state, _transfer())

    assert caught.value.reason == "fee_destination_required"
    assert state["accounts"]["alice"]["balance"] == 100
    assert state["accounts"]["bob"]["balance"] == 0
    assert state["accounts"]["@fees"]["balance"] == 0


def test_a11_f002_total_debit_includes_fee_for_funds_check() -> None:
    state = _econ_state(balance=25, fee_sink=True)
    apply_economics(state, _fee_policy(7))

    with pytest.raises(EconomicsApplyError, match="insufficient_funds") as caught:
        apply_economics(state, _transfer(amount=20))

    assert caught.value.reason == "insufficient_funds"
    assert caught.value.details["amount"] == 20
    assert caught.value.details["fee_amount"] == 7
    assert state["accounts"]["alice"]["balance"] == 25
    assert state["accounts"]["bob"]["balance"] == 0
    assert state["accounts"]["@fees"]["balance"] == 0


def test_a11_f002_zero_transfer_fee_remains_fee_free() -> None:
    state = _econ_state(balance=100)
    apply_economics(state, _fee_policy(0))

    result = apply_economics(state, _transfer())

    assert "fee_amount" not in result
    assert "fee_to" not in result
    assert state["accounts"]["alice"]["balance"] == 80
    assert state["accounts"]["bob"]["balance"] == 20
    assert state["accounts"]["@fees"]["balance"] == 0
