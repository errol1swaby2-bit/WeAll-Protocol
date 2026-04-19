from __future__ import annotations

from pathlib import Path

from weall.runtime.domain_dispatch import apply_tx
from weall.runtime.system_tx_engine import system_tx_emitter
from weall.runtime.tx_admission import TxEnvelope
from weall.tx.canon import load_tx_index_json


def _load_index():
    repo_root = Path(__file__).resolve().parents[1]
    return load_tx_index_json(repo_root / "generated" / "tx_index.json")


def test_content_escalation_auto_assigns_sole_active_juror() -> None:
    idx = _load_index()
    st = {
        "height": 0,
        "accounts": {
            "alice": {"nonce": 0, "poh_tier": 3, "banned": False, "locked": False},
            "juror1": {"nonce": 0, "poh_tier": 3, "banned": False, "locked": False},
        },
        "content": {
            "posts": {
                "p1": {
                    "post_id": "p1",
                    "author": "alice",
                    "body": "hello",
                    "created_nonce": 1,
                    "visibility": "public",
                    "locked": False,
                    "tags": [],
                    "group_id": None,
                    "labels": [],
                    "flags": [],
                    "deleted": False,
                }
            }
        },
        "roles": {"jurors": {"by_id": {"juror1": {"enrolled": True, "active": True}}, "active_set": ["juror1"]}},
        "system_queue": [],
    }

    apply_tx(
        st,
        TxEnvelope(
            tx_type="CONTENT_FLAG",
            signer="alice",
            nonce=2,
            payload={"target_type": "post", "target_id": "p1", "reason": "spam"},
            sig="",
            system=False,
        ),
    )

    post_h1 = system_tx_emitter(st, canon=idx, next_height=1, phase="post")
    assert "CONTENT_ESCALATE_TO_DISPUTE" in [env.tx_type for env in post_h1]
    for env in post_h1:
        apply_tx(st, env)

    post_h2 = system_tx_emitter(st, canon=idx, next_height=2, phase="post")
    types_h2 = [env.tx_type for env in post_h2]
    assert "DISPUTE_JUROR_ASSIGN" in types_h2
    for env in post_h2:
        apply_tx(st, env)

    disputes = st.get("disputes_by_id") or {}
    assert len(disputes) == 1
    dispute = next(iter(disputes.values()))
    assert dispute["stage"] == "juror_review"
    assert dispute["jurors"]["juror1"]["status"] == "assigned"
