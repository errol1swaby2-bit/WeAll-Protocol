from __future__ import annotations

import pytest

from weall.runtime.apply.economics import EconomicsApplyError, apply_economics
from weall.runtime.tx_admission import TxEnvelope


def _active_state() -> dict:
    return {
        "time": 1_000,
        "params": {"economic_unlock_time": 0, "economics_enabled": True},
        "accounts": {
            "@alice": {"balance": 1_000},
            "@bob": {"balance": 25},
            "@creator": {"balance": 0},
        },
        "economics": {},
    }


def _locked_state() -> dict:
    st = _active_state()
    st["time"] = 0
    st["params"]["economic_unlock_time"] = 999
    st["params"]["economics_enabled"] = False
    return st


def _tx(signer: str, payload: dict, nonce: int = 1) -> TxEnvelope:
    return TxEnvelope(tx_type="BALANCE_TRANSFER", signer=signer, nonce=nonce, payload=payload)


def test_balance_transfer_accepts_canonical_to_account_id() -> None:
    st = _active_state()

    res = apply_economics(
        st,
        _tx(
            "@alice",
            {
                "from_account_id": "@alice",
                "to_account_id": "@bob",
                "amount": 100,
                "memo": "hello",
                "purpose": "profile_wallet_send",
            },
        ),
    )

    assert res["applied"] == "BALANCE_TRANSFER"
    assert res["from"] == "@alice"
    assert res["to"] == "@bob"
    assert res["amount"] == 100
    assert st["accounts"]["@alice"]["balance"] == 900
    assert st["accounts"]["@bob"]["balance"] == 125
    assert (
        st["economics"]["transfers_by_id"][res["transfer_id"]]["purpose"] == "profile_wallet_send"
    )


def test_balance_transfer_keeps_legacy_to_alias() -> None:
    st = _active_state()

    res = apply_economics(st, _tx("@alice", {"to": "@bob", "amount": 10}))

    assert res["to"] == "@bob"
    assert st["accounts"]["@alice"]["balance"] == 990
    assert st["accounts"]["@bob"]["balance"] == 35


def test_balance_transfer_rejects_self_transfer_without_mutation() -> None:
    st = _active_state()
    before_accounts = {account_id: dict(account) for account_id, account in st["accounts"].items()}

    with pytest.raises(EconomicsApplyError) as ei:
        apply_economics(
            st,
            _tx(
                "@alice",
                {
                    "from_account_id": "@alice",
                    "to_account_id": "@alice",
                    "amount": 100,
                },
            ),
        )

    assert ei.value.reason == "self_transfer_forbidden"
    assert st["accounts"] == before_accounts
    assert "transfers_by_id" not in st.get("economics", {})


def test_balance_transfer_rejects_from_account_spoof() -> None:
    st = _active_state()

    with pytest.raises(EconomicsApplyError) as ei:
        apply_economics(
            st,
            _tx(
                "@alice",
                {
                    "from_account_id": "@bob",
                    "to_account_id": "@creator",
                    "amount": 10,
                },
            ),
        )

    assert ei.value.reason == "from_account_must_match_signer"
    assert st["accounts"]["@alice"]["balance"] == 1_000
    assert st["accounts"]["@bob"]["balance"] == 25
    assert st["accounts"]["@creator"]["balance"] == 0


def test_balance_transfer_remains_locked_before_activation() -> None:
    st = _locked_state()

    with pytest.raises(EconomicsApplyError) as ei:
        apply_economics(st, _tx("@alice", {"to_account_id": "@bob", "amount": 10}))

    assert ei.value.reason in {"economics_time_locked", "economics_disabled"}
    assert st["accounts"]["@alice"]["balance"] == 1_000
    assert st["accounts"]["@bob"]["balance"] == 25


def test_content_tip_indexes_by_content_and_creator() -> None:
    st = _active_state()

    res = apply_economics(
        st,
        _tx(
            "@alice",
            {
                "from_account_id": "@alice",
                "to_account_id": "@creator",
                "amount": 15,
                "memo": "great post",
                "purpose": "content_tip",
                "content_id": "post-1",
            },
            nonce=2,
        ),
    )

    transfer_id = res["transfer_id"]
    assert st["accounts"]["@alice"]["balance"] == 985
    assert st["accounts"]["@creator"]["balance"] == 15
    assert st["economics"]["tips_by_content"]["post-1"] == [transfer_id]
    assert st["economics"]["tips_by_creator"]["@creator"] == [transfer_id]
    assert st["economics"]["transfers_by_id"][transfer_id]["memo"] == "great post"


def test_transfer_id_is_idempotent() -> None:
    st = _active_state()
    env = _tx(
        "@alice",
        {
            "to_account_id": "@bob",
            "amount": 10,
            "transfer_id": "transfer-1",
        },
    )

    first = apply_economics(st, env)
    second = apply_economics(st, env)

    assert first["transfer_id"] == "transfer-1"
    assert second["deduped"] is True
    assert st["accounts"]["@alice"]["balance"] == 990
    assert st["accounts"]["@bob"]["balance"] == 35
    assert len(st["economics"]["transfers"]) == 1
