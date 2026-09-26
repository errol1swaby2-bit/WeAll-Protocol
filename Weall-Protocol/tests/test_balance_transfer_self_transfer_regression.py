from __future__ import annotations

import pytest

from weall.runtime.apply.economics import EconomicsApplyError, apply_economics
from weall.runtime.tx_admission_types import TxEnvelope


def test_balance_transfer_rejects_self_transfer_without_mutation() -> None:
    state = {
        "time": 1,
        "height": 1,
        "params": {
            "genesis_time": 0,
            "economic_unlock_time": 0,
            "economics_enabled": True,
        },
        "accounts": {
            "@alice": {"balance": 1_000},
        },
        "economics": {
            "fee_policy": {},
            "monetary_policy": {"issued": 0},
        },
    }
    before_accounts = {
        account_id: dict(account) for account_id, account in state["accounts"].items()
    }
    envelope = TxEnvelope(
        tx_type="BALANCE_TRANSFER",
        signer="@alice",
        nonce=1,
        payload={
            "from_account_id": "@alice",
            "to_account_id": "@alice",
            "amount": 100,
        },
    )

    with pytest.raises(EconomicsApplyError) as exc_info:
        apply_economics(state, envelope)

    assert exc_info.value.reason == "self_transfer_forbidden"
    assert state["accounts"] == before_accounts
    assert "transfers_by_id" not in state["economics"]
