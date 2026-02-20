# tests/test_admission.py
from __future__ import annotations

from pathlib import Path

from weall.ledger.state import LedgerView
from weall.runtime.tx_admission import TxEnvelope, admit_tx
from weall.tx.canon import load_tx_index_json


def _load_index():
    repo_root = Path(__file__).resolve().parents[1]
    canon_path = repo_root / "generated" / "tx_index.json"
    return load_tx_index_json(canon_path)


def _choose_nonce_test_tx(idx) -> str:
    """Pick a stable mempool-allowed tx with a production-valid payload."""

    # Prefer a tx with a simple, well-known strict schema.
    preferred = [
        "CONTENT_POST_CREATE",
        "TREASURY_CREATE",
        "PEER_ADVERTISE",
    ]
    names = {str(t.get("name") or "").strip() for t in idx.tx_types}
    for n in preferred:
        if n in names:
            # Must be mempool-allowed
            for tx in idx.tx_types:
                if tx.get("name") == n:
                    ctx = str(tx.get("context", "")).strip().lower()
                    if ctx != "block":
                        return n

    # Fallback: first non-block tx.
    for tx in idx.tx_types:
        ctx = str(tx.get("context", "")).strip().lower()
        if ctx != "block":
            return str(tx["name"])

    raise AssertionError("No mempool-allowed tx types found in canon")


def _valid_payload_for_tx(tx_type: str) -> dict:
    """Return a strict-schema-valid payload for the given tx_type.

    This keeps tests aligned with the production goal that clients must submit
    complete, schema-valid payloads.
    """
    t = str(tx_type or "").strip()
    if t == "CONTENT_POST_CREATE":
        return {"post_id": "p_nonce_test", "body": "hi"}
    if t == "TREASURY_CREATE":
        return {"treasury_id": "t_nonce_test", "name": "Nonce Test Treasury"}
    if t == "PEER_ADVERTISE":
        return {"endpoint": "http://127.0.0.1:8000"}

    # Generic fallback: some txs require fields we don't know here.
    # In that case, tests should not be using that tx for nonce behavior.
    return {}


def test_mempool_rejects_block_only_txs() -> None:
    idx = _load_index()

    # Find any block-only tx in the canon that is NOT receipt_only.
    # (receipt_only gets its own dedicated test below.)
    block_only_name = None
    for tx in idx.tx_types:
        ctx = str(tx.get("context", "")).strip().lower()
        receipt_only = bool(tx.get("receipt_only", False))
        if ctx == "block" and not receipt_only:
            block_only_name = tx["name"]
            break

    # If your canon currently has no block-only non-receipt txs, skip hard failure.
    if not block_only_name:
        return

    ledger = LedgerView(
        accounts={
            "alice": {"nonce": 0, "poh_tier": 3, "banned": False, "locked": False, "reputation": 10},
        },
        roles={},
    )

    env = TxEnvelope(
        tx_type=block_only_name,
        signer="alice",
        nonce=1,
        payload={},
        sig="deadbeef",
        parent=None,
    )

    ok, rej = admit_tx(env.to_json(), ledger, idx, context="mempool")
    assert not ok
    assert rej is not None
    assert rej.code == "block_only"


def test_mempool_rejects_receipt_only_txs() -> None:
    idx = _load_index()

    # Find any receipt-only tx in the canon (typically block-context).
    receipt_only_name = None
    for tx in idx.tx_types:
        if bool(tx.get("receipt_only", False)):
            receipt_only_name = tx["name"]
            break

    # If your canon currently has no receipt-only txs, skip hard failure.
    if not receipt_only_name:
        return

    ledger = LedgerView(
        accounts={
            "alice": {"nonce": 0, "poh_tier": 3, "banned": False, "locked": False, "reputation": 10},
        },
        roles={},
    )

    # Even if a parent is provided, mempool context must reject receipt-only txs.
    env = TxEnvelope(
        tx_type=receipt_only_name,
        signer="alice",
        nonce=1,
        payload={},
        sig="deadbeef",
        parent="txid:parent",
        system=True,
    )

    ok, rej = admit_tx(env.to_json(), ledger, idx, context="mempool")
    assert not ok
    assert rej is not None
    assert rej.code == "receipt_only"


def test_mempool_enforces_next_nonce() -> None:
    idx = _load_index()

    mempool_name = _choose_nonce_test_tx(idx)
    payload = _valid_payload_for_tx(mempool_name)
    assert payload, f"nonce test requires a valid payload for tx_type={mempool_name}"

    ledger = LedgerView(
        accounts={
            "alice": {"nonce": 5, "poh_tier": 3, "banned": False, "locked": False, "reputation": 10},
        },
        roles={},
    )

    # wrong nonce (should be 6)
    env = TxEnvelope(
        tx_type=mempool_name,
        signer="alice",
        nonce=7,
        payload=payload,
        sig="deadbeef",
        parent=None,
    )
    ok, rej = admit_tx(env.to_json(), ledger, idx, context="mempool")
    assert not ok
    assert rej is not None
    assert rej.code == "bad_nonce"
