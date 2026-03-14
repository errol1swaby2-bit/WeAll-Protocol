# tests/test_apply_storage_peer_validator.py
from __future__ import annotations

import pytest

from weall.runtime.domain_apply import ApplyError, apply_tx
from weall.runtime.tx_admission import TxEnvelope


def _env(
    tx_type: str,
    signer: str,
    nonce: int,
    payload: dict | None = None,
    *,
    system: bool = False,
    parent: str | None = None,
) -> TxEnvelope:
    # Receipt-only SYSTEM txs must carry a parent. For tests, default to a deterministic stub.
    if system and not parent:
        parent = f"p:{max(0, int(nonce) - 1)}"
    return TxEnvelope(
        tx_type=tx_type,
        signer=signer,
        nonce=nonce,
        payload=payload or {},
        sig="sig",
        parent=parent,
        system=system,
    )


def test_storage_challenge_issue_and_resolve() -> None:
    st = {}

    # Challenge issuance requires a lease_id; leases require an active offer.
    offer_meta = apply_tx(
        st,
        _env(
            "STORAGE_OFFER_CREATE",
            signer="op1",
            nonce=1,
            payload={"offer_id": "o1", "cid": "cid:demo", "capacity_bytes": 1, "price": 1},
        ),
    )
    assert offer_meta and offer_meta["applied"] == "STORAGE_OFFER_CREATE"

    lease_meta = apply_tx(
        st,
        _env(
            "STORAGE_LEASE_CREATE",
            signer="alice",
            nonce=2,
            payload={"lease_id": "l1", "offer_id": "o1", "duration_blocks": 5},
        ),
    )
    assert lease_meta and lease_meta["applied"] == "STORAGE_LEASE_CREATE"

    meta = apply_tx(
        st,
        _env(
            "STORAGE_CHALLENGE_ISSUE",
            signer="SYSTEM",
            nonce=3,
            payload={"lease_id": "l1", "operator_id": "op1", "account_id": "alice"},
            system=True,
        ),
    )
    assert meta and meta["applied"] == "STORAGE_CHALLENGE_ISSUE"
    cid = meta["challenge_id"]

    assert st["storage"]["challenges"][cid]["lease_id"] == "l1"
    assert st["storage"]["challenges"][cid]["operator_id"] == "op1"
    assert st["storage"]["challenges"][cid]["status"] == "open"

    # Canon intent: operator responds (USER origin) rather than a SYSTEM "resolve" tx.
    meta2 = apply_tx(
        st,
        _env(
            "STORAGE_CHALLENGE_RESPOND",
            signer="op1",
            nonce=4,
            payload={"challenge_id": cid, "response_cid": "cid:resp"},
            system=False,
        ),
    )
    assert meta2 and meta2["applied"] == "STORAGE_CHALLENGE_RESPOND"
    assert st["storage"]["challenges"][cid]["status"] == "responded"


def test_peer_ban_set_receipt_requires_system() -> None:
    st = {}
    with pytest.raises(ApplyError):
        apply_tx(st, _env("PEER_BAN_SET", signer="SYSTEM", nonce=1, payload={"peer_id": "p1", "banned": True}, system=False))

    meta = apply_tx(st, _env("PEER_BAN_SET", signer="SYSTEM", nonce=2, payload={"peer_id": "p1", "banned": True}, system=True))
    assert meta and meta["applied"] == "PEER_BAN_SET"
    assert st["peers"]["bans"]["p1"]["banned"] is True


def test_validator_set_update_receipt_requires_system() -> None:
    st = {}
    with pytest.raises(ApplyError):
        apply_tx(
            st,
            _env(
                "VALIDATOR_SET_UPDATE",
                signer="SYSTEM",
                nonce=1,
                payload={"active_set": ["v1", "v2"]},
                system=False,
            ),
        )

    meta = apply_tx(
        st,
        _env(
            "VALIDATOR_SET_UPDATE",
            signer="SYSTEM",
            nonce=2,
            payload={"active_set": ["v1", "v2"]},
            system=True,
        ),
    )
    assert meta and meta["applied"] == "VALIDATOR_SET_UPDATE"
    assert st["roles"]["validators"]["active_set"] == ["v1", "v2"]
