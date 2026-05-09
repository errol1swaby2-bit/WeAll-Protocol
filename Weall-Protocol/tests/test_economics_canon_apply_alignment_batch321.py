from __future__ import annotations

from weall.runtime.apply.economics import apply_economics
from weall.runtime.econ_phase import is_economic_system_tx, is_economic_user_tx
from weall.runtime.tx_admission_types import TxEnvelope


def _econ_state() -> dict:
    return {
        "time": 1000,
        "params": {"genesis_time": 0, "economic_unlock_time": 1, "economics_enabled": True},
        "accounts": {
            "alice": {"balance": 10, "poh_tier": 0, "nonce": 0, "banned": False, "locked": False},
            "@fees": {"balance": 0, "poh_tier": 0, "nonce": 0, "banned": False, "locked": False},
        },
    }


def test_economic_user_tx_classification_uses_origin_not_mempool_context_batch321() -> None:
    assert is_economic_user_tx("BALANCE_TRANSFER") is True
    assert is_economic_system_tx("BALANCE_TRANSFER") is False
    assert is_economic_user_tx("FEE_PAY") is True
    assert is_economic_system_tx("FEE_PAY") is False
    assert is_economic_user_tx("ECONOMICS_ACTIVATION") is False
    assert is_economic_system_tx("ECONOMICS_ACTIVATION") is True


def test_fee_pay_user_origin_applies_without_system_context_batch321() -> None:
    state = _econ_state()
    env = TxEnvelope(
        tx_type="FEE_PAY",
        signer="alice",
        nonce=1,
        system=False,
        payload={"tx_id": "tx-1", "tx_type": "BALANCE_TRANSFER", "amount": 3, "to_account_id": "@fees"},
    )

    result = apply_economics(state, env)

    assert result == {"applied": "FEE_PAY", "from": "alice", "to": "@fees", "amount": 3}
    assert state["accounts"]["alice"]["balance"] == 7
    assert state["accounts"]["@fees"]["balance"] == 3
    assert state["economics"]["fee_payments"][0]["amount"] == 3


def test_fee_pay_rejects_spoofed_from_account_batch321() -> None:
    state = _econ_state()
    env = TxEnvelope(
        tx_type="FEE_PAY",
        signer="alice",
        nonce=1,
        system=False,
        payload={"from_account_id": "mallory", "amount": 1},
    )

    try:
        apply_economics(state, env)
        assert False, "spoofed fee payer must be rejected"
    except Exception as exc:
        assert getattr(exc, "reason", "") == "fee_pay_signer_mismatch"
