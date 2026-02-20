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


def test_dispute_vote_submit_enqueues_resolve_and_final_receipt_chain() -> None:
    idx = _load_index()

    # Minimal ledger skeleton
    st = {
        "height": 0,
        "accounts": {"alice": {"nonce": 0, "poh_tier": 3, "banned": False, "locked": False, "reputation": 10}},
        "roles": {},
        "system_queue": [],
    }

    # Open a dispute
    apply_tx(
        st,
        TxEnvelope(
            tx_type="DISPUTE_OPEN",
            signer="alice",
            nonce=1,
            payload={"dispute_id": "d1", "target_type": "content", "target_id": "c1", "reason": "test"},
            sig="",
            system=False,
        ),
    )

    # Submit a vote with an MVP resolution object -> should enqueue DISPUTE_RESOLVE
    apply_tx(
        st,
        TxEnvelope(
            tx_type="DISPUTE_VOTE_SUBMIT",
            signer="alice",
            nonce=2,
            payload={
                "dispute_id": "d1",
                "vote": "yes",
                "resolution": {
                    "summary": "lock bob",
                    "actions": [
                        {"tx_type": "ACCOUNT_LOCK", "payload": {"target": "bob"}},
                    ],
                },
            },
            sig="",
            system=False,
        ),
    )

    # Ensure the resolve receipt is scheduled for the next produced block (height=1), post-phase.
    q = st.get("system_queue")
    assert isinstance(q, list)
    resolve_items = [x for x in q if isinstance(x, dict) and x.get("tx_type") == "DISPUTE_RESOLVE"]
    assert len(resolve_items) == 1
    assert int(resolve_items[0].get("due_height")) == 1
    assert str(resolve_items[0].get("phase")) == "post"
    assert str(resolve_items[0].get("parent") or "").startswith("tx:alice:2")

    # Emit + apply DISPUTE_RESOLVE at height=1.
    post_h1 = system_tx_emitter(st, canon=idx, next_height=1, phase="post")
    types_h1 = [e.tx_type for e in post_h1]
    assert "DISPUTE_RESOLVE" in types_h1

    for env in post_h1:
        apply_tx(st, env)

    # After applying DISPUTE_RESOLVE, follow-up receipts/actions are scheduled for height=2.
    q2 = st.get("system_queue")
    assert isinstance(q2, list)
    final_items = [x for x in q2 if isinstance(x, dict) and x.get("tx_type") == "DISPUTE_FINAL_RECEIPT"]
    assert len(final_items) == 1
    assert int(final_items[0].get("due_height")) == 2
    assert str(final_items[0].get("phase")) == "post"

    lock_items = [x for x in q2 if isinstance(x, dict) and x.get("tx_type") == "ACCOUNT_LOCK"]
    assert len(lock_items) == 1
    assert int(lock_items[0].get("due_height")) == 2

    # Emit + apply follow-ups at height=2.
    post_h2 = system_tx_emitter(st, canon=idx, next_height=2, phase="post")
    types_h2 = [e.tx_type for e in post_h2]
    assert "DISPUTE_FINAL_RECEIPT" in types_h2
    assert "ACCOUNT_LOCK" in types_h2

    for env in post_h2:
        apply_tx(st, env)

    # ACCOUNT_LOCK should have taken effect.
    assert st["accounts"]["bob"]["locked"] is True
