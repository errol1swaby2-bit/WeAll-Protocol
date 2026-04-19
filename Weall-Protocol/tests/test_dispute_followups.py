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
        "accounts": {
            "alice": {"nonce": 0, "poh_tier": 3, "banned": False, "locked": False, "reputation": 10}
        },
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
            payload={
                "dispute_id": "d1",
                "target_type": "content",
                "target_id": "c1",
                "reason": "test",
            },
            sig="",
            system=False,
        ),
    )

    # Strict mode: juror authorization must be explicit.
    # Assign alice as juror (SYSTEM) and have alice accept before voting.
    apply_tx(
        st,
        TxEnvelope(
            tx_type="DISPUTE_JUROR_ASSIGN",
            signer="SYSTEM",
            nonce=1,
            payload={"dispute_id": "d1", "juror": "alice"},
            sig="",
            parent="tx:alice:1",
            system=True,
        ),
    )

    apply_tx(
        st,
        TxEnvelope(
            tx_type="DISPUTE_JUROR_ACCEPT",
            signer="alice",
            nonce=2,
            payload={"dispute_id": "d1"},
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
            nonce=3,
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

    # DISPUTE_RESOLVE now applies inline as soon as threshold is met.
    dispute = st["disputes_by_id"]["d1"]
    assert dispute["resolved"] is True
    assert dispute["stage"] == "resolved"

    # Follow-up receipts/actions are still scheduled for the next produced block.
    q2 = st.get("system_queue")
    assert isinstance(q2, list)
    resolve_items = [x for x in q2 if isinstance(x, dict) and x.get("tx_type") == "DISPUTE_RESOLVE"]
    assert len(resolve_items) == 0
    final_items = [
        x for x in q2 if isinstance(x, dict) and x.get("tx_type") == "DISPUTE_FINAL_RECEIPT"
    ]
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


def test_affirmative_content_dispute_resolution_enforces_content_visibility() -> None:
    idx = _load_index()
    st = {
        "height": 0,
        "accounts": {
            "alice": {"nonce": 0, "poh_tier": 3, "banned": False, "locked": False, "reputation": 10}
        },
        "roles": {},
        "system_queue": [],
        "content": {
            "posts": {
                "post:alice:1": {
                    "id": "post:alice:1",
                    "author": "alice",
                    "body": "bad post",
                    "visibility": "public",
                    "deleted": False,
                    "locked": False,
                    "labels": [],
                }
            },
            "comments": {},
        },
    }

    apply_tx(
        st,
        TxEnvelope(
            tx_type="DISPUTE_OPEN",
            signer="alice",
            nonce=1,
            payload={
                "dispute_id": "d-content",
                "target_type": "content",
                "target_id": "post:alice:1",
                "reason": "policy violation",
            },
            sig="",
            system=False,
        ),
    )
    apply_tx(
        st,
        TxEnvelope(
            tx_type="DISPUTE_JUROR_ASSIGN",
            signer="SYSTEM",
            nonce=1,
            payload={"dispute_id": "d-content", "juror": "alice"},
            sig="",
            parent="tx:alice:1",
            system=True,
        ),
    )
    apply_tx(
        st,
        TxEnvelope(
            tx_type="DISPUTE_JUROR_ACCEPT",
            signer="alice",
            nonce=2,
            payload={"dispute_id": "d-content"},
            sig="",
            system=False,
        ),
    )
    apply_tx(
        st,
        TxEnvelope(
            tx_type="DISPUTE_VOTE_SUBMIT",
            signer="alice",
            nonce=3,
            payload={
                "dispute_id": "d-content",
                "vote": "yes",
            },
            sig="",
            system=False,
        ),
    )

    dispute = st["disputes_by_id"]["d-content"]
    assert dispute["resolved"] is True
    assert dispute["stage"] == "resolved"
    assert isinstance(dispute.get("resolution"), dict)
    actions = dispute["resolution"].get("actions")
    assert isinstance(actions, list) and any(a.get("tx_type") == "CONTENT_VISIBILITY_SET" for a in actions)

    post = st["content"]["posts"]["post:alice:1"]
    assert post["visibility"] == "deleted"
    assert post["deleted"] is True
    assert post["locked"] is True
    assert "policy_violation" in post["labels"]
