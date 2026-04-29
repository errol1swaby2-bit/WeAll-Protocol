from __future__ import annotations

import pytest

from weall.runtime.domain_apply import apply_tx
from weall.runtime.errors import ApplyError
from weall.runtime.tx_admission import TxEnvelope


def _env(
    tx_type: str,
    payload: dict,
    *,
    signer: str = "alice",
    nonce: int = 1,
    system: bool = False,
    parent: str | None = None,
) -> TxEnvelope:
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
        "roles": {"emissaries": {"seated": ["alice", "bob"]}},
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
                    "threshold": 1,
                    "allowed_signers": ["alice", "bob"],
                    "signatures": {},
                    "earliest_execute_height": 1,
                    "payload": {"amount": 5},
                }
            }
        },
    }


def _sign(st: dict, *, signer: str = "alice", nonce: int = 1) -> dict:
    return apply_tx(
        st,
        _env(
            "TREASURY_SPEND_SIGN",
            {"treasury_id": "t1", "spend_id": "sp1"},
            signer=signer,
            nonce=nonce,
        ),
    )


def test_treasury_spend_sign_rejects_after_execute() -> None:
    st = _mk_state()
    st["treasury"]["spends"]["sp1"]["status"] = "executed"

    with pytest.raises(ApplyError) as ei:
        _sign(st, signer="bob", nonce=1)
    assert ei.value.code == "forbidden"
    assert ei.value.reason == "spend_executed"


def test_treasury_spend_sign_rejects_after_cancel() -> None:
    st = _mk_state()
    st["treasury"]["spends"]["sp1"]["status"] = "canceled"

    with pytest.raises(ApplyError) as ei:
        _sign(st, signer="bob", nonce=1)
    assert ei.value.code == "forbidden"
    assert ei.value.reason == "spend_canceled"


def test_treasury_spend_sign_rejects_after_expire() -> None:
    st = _mk_state()
    st["treasury"]["spends"]["sp1"]["status"] = "expired"

    with pytest.raises(ApplyError) as ei:
        _sign(st, signer="alice", nonce=1)
    assert ei.value.code == "forbidden"
    assert ei.value.reason == "spend_expired"
