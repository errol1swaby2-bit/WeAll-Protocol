from __future__ import annotations

import pytest

from weall.runtime.apply.economics import EconomicsApplyError, apply_economics
from weall.runtime.tx_admission_types import TxEnvelope


def _active_state() -> dict:
    return {
        "time": 1,
        "height": 1,
        "params": {"genesis_time": 0, "economic_unlock_time": 0, "economics_enabled": True},
        "accounts": {
            "@alice": {"balance": 1_000},
            "@bob": {"balance": 25},
            "@creator": {"balance": 0},
        },
        "economics": {"fee_policy": {}, "monetary_policy": {"issued": 0}},
    }


def _locked_state() -> dict:
    st = _active_state()
    st["time"] = 0
    st["params"]["economic_unlock_time"] = 999
    st["params"]["economics_enabled"] = False
    return st


def _tx(signer: str, payload: dict, nonce: int = 1) -> TxEnvelope:
    return TxEnvelope(tx_type="BALANCE_TRANSFER", signer=signer, nonce=nonce, payload=payload)


def test_balance_transfer_accepts_canonical_to_account_id_batch483() -> None:
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
    assert st["economics"]["transfers_by_id"][res["transfer_id"]]["purpose"] == "profile_wallet_send"


def test_balance_transfer_keeps_legacy_to_alias_batch483() -> None:
    st = _active_state()

    res = apply_economics(st, _tx("@alice", {"to": "@bob", "amount": 10}))

    assert res["to"] == "@bob"
    assert st["accounts"]["@alice"]["balance"] == 990
    assert st["accounts"]["@bob"]["balance"] == 35


def test_balance_transfer_rejects_from_account_spoof_batch483() -> None:
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


def test_balance_transfer_remains_locked_before_activation_batch484() -> None:
    st = _locked_state()

    with pytest.raises(EconomicsApplyError) as ei:
        apply_economics(st, _tx("@alice", {"to_account_id": "@bob", "amount": 10}))

    assert ei.value.reason in {"economics_time_locked", "economics_disabled"}
    assert st["accounts"]["@alice"]["balance"] == 1_000
    assert st["accounts"]["@bob"]["balance"] == 25


def test_content_tip_indexes_by_content_and_creator_batch484() -> None:
    st = _active_state()

    res = apply_economics(
        st,
        _tx(
            "@alice",
            {
                "from_account_id": "@alice",
                "to_account_id": "@creator",
                "amount": 250,
                "purpose": "content_tip",
                "content_id": "post:abc",
                "memo": "great post",
            },
        ),
    )

    assert res["tip_indexed"] is True
    assert st["accounts"]["@alice"]["balance"] == 750
    assert st["accounts"]["@creator"]["balance"] == 250

    by_content = st["economics"]["tips_by_content_id"]["post:abc"]
    assert by_content["count"] == 1
    assert by_content["total_amount"] == 250
    assert res["transfer_id"] in by_content["tips"]

    by_creator = st["economics"]["tips_by_creator"]["@creator"]
    assert by_creator["count"] == 1
    assert by_creator["total_amount"] == 250
    assert res["transfer_id"] in by_creator["tips"]


def test_transfer_id_dedupe_prevents_double_spend_on_replay_batch484() -> None:
    st = _active_state()
    payload = {"to_account_id": "@bob", "amount": 50, "transfer_id": "transfer:test"}

    first = apply_economics(st, _tx("@alice", payload, nonce=7))
    replay = apply_economics(st, _tx("@alice", payload, nonce=7))

    assert first["deduped"] is False
    assert replay["deduped"] is True
    assert st["accounts"]["@alice"]["balance"] == 950
    assert st["accounts"]["@bob"]["balance"] == 75

def test_legacy_plain_balance_transfer_receipt_shape_is_preserved_batch486() -> None:
    st = _active_state()

    res = apply_economics(st, _tx("@alice", {"to": "@bob", "amount": 5}, nonce=44))

    assert res == {"applied": "BALANCE_TRANSFER", "from": "@alice", "to": "@bob", "amount": 5}
    assert st["accounts"]["@alice"]["balance"] == 995
    assert st["accounts"]["@bob"]["balance"] == 30

