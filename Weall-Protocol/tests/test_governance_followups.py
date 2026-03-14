from __future__ import annotations

from pathlib import Path

from weall.runtime.domain_dispatch import apply_tx
from weall.runtime.system_tx_engine import system_tx_emitter
from weall.runtime.tx_admission import TxEnvelope
from weall.tx.canon import load_tx_index_json


def _load_index():
    repo_root = Path(__file__).resolve().parents[1]
    canon_path = repo_root / "generated" / "tx_index.json"
    return load_tx_index_json(canon_path)


def test_gov_execute_enqueues_execution_receipt() -> None:
    idx = _load_index()

    st = {
        "height": 0,
        "accounts": {
            "alice": {"nonce": 0, "poh_tier": 3, "banned": False, "locked": False, "reputation": 10},
            "SYSTEM": {"nonce": 0, "poh_tier": 3, "banned": False, "locked": False, "reputation": 10},
        },
        "roles": {},
        "system_queue": [],
    }

    # Create proposal (mempool tx)
    apply_tx(
        st,
        TxEnvelope(
            tx_type="GOV_PROPOSAL_CREATE",
            signer="alice",
            nonce=1,
            payload={"proposal_id": "p1", "title": "t"},
            sig="",
            system=False,
        ),
    )

    # Apply GOV_EXECUTE (receipt-only, SYSTEM) as if it arrived from system queue at height=1
    apply_tx(
        st,
        TxEnvelope(
            tx_type="GOV_EXECUTE",
            signer="SYSTEM",
            nonce=1,
            payload={"proposal_id": "p1", "_due_height": 1, "_system_queue_id": "qid-exe"},
            sig="",
            parent="tx:alice:1",
            system=True,
        ),
    )

    q = st.get("system_queue")
    assert isinstance(q, list)
    rec_items = [x for x in q if isinstance(x, dict) and x.get("tx_type") == "GOV_EXECUTION_RECEIPT"]
    assert len(rec_items) == 1
    assert int(rec_items[0].get("due_height")) == 2
    assert str(rec_items[0].get("phase")) == "post"
    assert str(rec_items[0].get("parent") or "").strip() != ""

    # Emit + apply receipt at height=2
    post_h2 = system_tx_emitter(st, canon=idx, next_height=2, phase="post")
    assert "GOV_EXECUTION_RECEIPT" in [e.tx_type for e in post_h2]
    for env in post_h2:
        apply_tx(st, env)

    log = st.get("gov_execution_receipts")
    assert isinstance(log, list)
    assert len(log) >= 1


def test_gov_finalize_enqueues_proposal_receipt() -> None:
    idx = _load_index()

    st = {
        "height": 0,
        "accounts": {
            "alice": {"nonce": 0, "poh_tier": 3, "banned": False, "locked": False, "reputation": 10},
            "SYSTEM": {"nonce": 0, "poh_tier": 3, "banned": False, "locked": False, "reputation": 10},
        },
        "roles": {},
        "system_queue": [],
    }

    apply_tx(
        st,
        TxEnvelope(
            tx_type="GOV_PROPOSAL_CREATE",
            signer="alice",
            nonce=1,
            payload={"proposal_id": "p2", "title": "t"},
            sig="",
            system=False,
        ),
    )

    # Apply finalize receipt-only tx as if produced by GovExecutor at height=1
    apply_tx(
        st,
        TxEnvelope(
            tx_type="GOV_PROPOSAL_FINALIZE",
            signer="SYSTEM",
            nonce=1,
            payload={"proposal_id": "p2", "_due_height": 1, "_system_queue_id": "qid-fin"},
            sig="",
            parent="tx:alice:1",
            system=True,
        ),
    )

    q = st.get("system_queue")
    assert isinstance(q, list)
    rec_items = [x for x in q if isinstance(x, dict) and x.get("tx_type") == "GOV_PROPOSAL_RECEIPT"]
    assert len(rec_items) == 1
    assert int(rec_items[0].get("due_height")) == 2
    assert str(rec_items[0].get("phase")) == "post"
    assert str(rec_items[0].get("parent") or "").strip() != ""

    post_h2 = system_tx_emitter(st, canon=idx, next_height=2, phase="post")
    assert "GOV_PROPOSAL_RECEIPT" in [e.tx_type for e in post_h2]
    for env in post_h2:
        apply_tx(st, env)

    log = st.get("gov_proposal_receipts")
    assert isinstance(log, list)
    assert len(log) >= 1
