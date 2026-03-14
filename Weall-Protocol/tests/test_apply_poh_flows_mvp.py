from __future__ import annotations

from typing import Any, Dict

from weall.runtime.domain_dispatch import apply_tx
from weall.runtime.tx_admission_types import TxEnvelope

Json = Dict[str, Any]


def _env(
    tx_type: str,
    payload: Json | None = None,
    *,
    signer: str = "alice",
    nonce: int = 1,
    system: bool = False,
) -> Json:
    return {
        "tx_type": tx_type,
        "signer": signer,
        "nonce": nonce,
        "sig": "",
        "payload": payload or {},
        "system": bool(system),
    }


def test_poh_challenge_open_and_resolve() -> None:
    st: Json = {}

    meta = apply_tx(
        st,
        _env(
            "POH_CHALLENGE_OPEN",
            {"account_id": "bob", "reason": "suspected_dup"},
            signer="alice",
            nonce=1,
        ),
    )
    assert meta and meta["applied"] == "POH_CHALLENGE_OPEN"
    cid = meta["challenge_id"]

    assert st["poh"]["challenges"][cid]["account_id"] == "bob"
    assert st["poh"]["challenges"][cid]["status"] == "open"

    # Production semantics:
    # - system receipt
    # - requires parent
    # - uses "resolution": "dismissed" | "upheld"
    env2 = _env(
        "POH_CHALLENGE_RESOLVE",
        {"challenge_id": cid, "resolution": "dismissed", "note": "ok"},
        signer="SYSTEM",
        nonce=2,
        system=True,
    )
    # parent required for receipt-only/system apply in production path
    env2["parent"] = "txid:poh_challenge_open"

    meta2 = apply_tx(st, TxEnvelope.from_json(env2))
    assert meta2 and meta2["applied"] == "POH_CHALLENGE_RESOLVE"
    assert meta2["challenge_id"] == cid
    assert meta2["resolution"] == "dismissed"

    assert st["poh"]["challenges"][cid]["status"] == "resolved"
    assert st["poh"]["challenges"][cid]["resolution"] == "dismissed"
