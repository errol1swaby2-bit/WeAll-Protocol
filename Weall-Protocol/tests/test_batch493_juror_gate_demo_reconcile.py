from __future__ import annotations

from weall.runtime.gate_expr import eval_gate
from weall.runtime.domain_dispatch import apply_tx
from weall.runtime.errors import ApplyError
from weall.runtime.tx_admission import TxEnvelope


def _tier2() -> dict:
    return {"poh_tier": 2, "banned": False, "locked": False, "status": "active"}


def test_assigned_dispute_juror_gate_requires_explicit_rehearsal_scope_batch493() -> None:
    base = {
        "accounts": {"@observer-user": _tier2()},
        "roles": {"jurors": {"by_id": {}, "active_set": []}},
        "disputes_by_id": {
            "d1": {
                "id": "d1",
                "target_owner": "@other",
                "assigned_jurors": ["@observer-user"],
                "eligible_juror_ids": ["@observer-user"],
                "jurors": {"@observer-user": {"status": "assigned"}},
            }
        },
        "params": {},
    }
    ok_default, _ = eval_gate("Juror", signer="@observer-user", state=base, payload={"dispute_id": "d1"})
    assert ok_default is False

    controlled = dict(base)
    controlled["chain_id"] = "weall-controlled-devnet"
    ok_controlled, meta = eval_gate("Juror", signer="@observer-user", state=controlled, payload={"dispute_id": "d1"})
    assert ok_controlled is True, meta


def test_seeded_demo_assignment_compat_does_not_allow_accept_or_vote_batch493() -> None:
    st = {
        "accounts": {"@author": _tier2(), "SYSTEM": _tier2()},
        "roles": {},
        "params": {"seeded_demo_review_fallback": True},
        "content": {"posts": {"p1": {"post_id": "p1", "author": "@author"}}, "comments": {}},
        "disputes_by_id": {
            "d1": {
                "id": "d1",
                "target_type": "content",
                "target_id": "p1",
                "target_owner": "@author",
                "jurors": {},
                "votes": {},
            }
        },
    }
    apply_tx(st, TxEnvelope(tx_type="DISPUTE_JUROR_ASSIGN", signer="SYSTEM", nonce=1, payload={"dispute_id": "d1", "juror": "@author"}, system=True))

    try:
        apply_tx(st, TxEnvelope(tx_type="DISPUTE_JUROR_ACCEPT", signer="@author", nonce=1, payload={"dispute_id": "d1"}))
    except ApplyError as exc:
        assert exc.reason == "target_owner_cannot_review"
    else:
        raise AssertionError("target owner accepted their own seeded-demo dispute")
