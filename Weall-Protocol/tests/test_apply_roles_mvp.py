# tests/test_apply_roles_mvp.py
from __future__ import annotations

import pytest

from weall.runtime.domain_apply import ApplyError, apply_tx
from weall.runtime.tx_admission import TxEnvelope


def _env(
    tx_type: str,
    payload: dict,
    signer: str = "alice",
    nonce: int = 1,
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
        payload=payload,
        sig="sig",
        parent=parent,
        system=system,
    )


def test_treasury_create_then_set_signers() -> None:
    st = {}

    # create
    meta = apply_tx(st, _env("TREASURY_CREATE", {"treasury_id": "t1"}))
    assert meta and meta["applied"] == "TREASURY_CREATE"

    # set signers
    meta2 = apply_tx(st, _env("TREASURY_SIGNERS_SET", {"treasury_id": "t1", "signers": ["alice", "bob"], "threshold": 2}))
    assert meta2 and meta2["applied"] == "TREASURY_SIGNERS_SET"

    assert st["roles"]["treasuries_by_id"]["t1"]["signers"] == ["alice", "bob"]
    assert st["roles"]["treasuries_by_id"]["t1"]["threshold"] == 2


def test_validator_set_create_and_update() -> None:
    st = {}

    # Canon intent:
    # - VALIDATOR_SET_UPDATE is a SYSTEM receipt that sets the active validator set
    # - There is no separate VALIDATOR_SET_CREATE in the current canon
    meta = apply_tx(
        st,
        _env(
            "VALIDATOR_SET_UPDATE",
            {"active_set": ["v1", "v2"]},
            signer="SYSTEM",
            nonce=1,
            system=True,
        ),
    )
    assert meta and meta["applied"] == "VALIDATOR_SET_UPDATE"
    assert st["roles"]["validators"]["active_set"] == ["v1", "v2"]

    meta2 = apply_tx(
        st,
        _env(
            "VALIDATOR_SET_UPDATE",
            {"active_set": ["v1", "v3", "v3"]},
            signer="SYSTEM",
            nonce=2,
            system=True,
        ),
    )
    assert meta2 and meta2["applied"] == "VALIDATOR_SET_UPDATE"
    # Dedupe is enforced in apply_consensus
    assert st["roles"]["validators"]["active_set"] == ["v1", "v3"]


def test_invalid_threshold_rejected() -> None:
    st = {}
    apply_tx(st, _env("TREASURY_CREATE", {"treasury_id": "t1"}))
    with pytest.raises(ApplyError):
        apply_tx(st, _env("TREASURY_SIGNERS_SET", {"treasury_id": "t1", "signers": ["alice"], "threshold": 2}))
