from __future__ import annotations

import pytest

from weall.runtime.domain_dispatch import apply_tx
from weall.runtime.gate_expr import eval_gate
from weall.runtime.tx_admission import TxEnvelope


def _env(tx_type: str, signer: str, nonce: int, payload: dict, *, system: bool = False) -> TxEnvelope:
    return TxEnvelope(tx_type=tx_type, signer=signer, nonce=nonce, payload=payload, sig="sig", system=system)


def _state() -> dict:
    return {
        "height": 0,
        "accounts": {
            "@errol": {"nonce": 0, "poh_tier": 2, "banned": False, "locked": False, "reputation_milli": 6000},
            "@genesis": {"nonce": 0, "poh_tier": 2, "banned": False, "locked": False, "reputation_milli": 6000},
        },
        "roles": {"jurors": {"by_id": {}, "active_set": []}, "validators": {"active_set": ["@genesis"]}},
        "content": {
            "posts": {
                "post:@genesis:1": {
                    "id": "post:@genesis:1",
                    "author": "@genesis",
                    "body": "reported content",
                    "visibility": "public",
                    "deleted": False,
                    "locked": False,
                }
            },
            "comments": {},
            "reactions": {},
            "flags": {},
            "media": {},
            "media_bindings": {},
            "moderation": {"receipts": [], "targets": {}},
        },
        "system_queue": [],
    }


def test_tier2_account_must_explicitly_opt_into_juror_responsibility_before_gate_passes() -> None:
    st = _state()
    st["disputes_by_id"] = {
        "d1": {"dispute_id": "d1", "stage": "juror_review", "jurors": {"@errol": {"status": "assigned"}}}
    }

    ok, _ = eval_gate("Juror", signer="@errol", ledger=st, payload={"dispute_id": "d1"})
    assert ok is False

    apply_tx(st, _env("ROLE_JUROR_ENROLL", "@errol", 1, {"account_id": "@errol"}))
    rec = st["roles"]["jurors"]["by_id"]["@errol"]
    assert rec["active"] is True
    assert rec["status"] == "active"
    assert rec["responsibilities"]["reviewer"] == {}

    apply_tx(st, _env("REVIEWER_LANE_OPT_IN", "@errol", 2, {"account_id": "@errol", "lane": "dispute_review"}))
    ok, meta = eval_gate("Juror", signer="@errol", ledger=st, payload={"dispute_id": "d1"})
    assert ok is True, meta
    assert rec["responsibilities"]["reviewer"]["dispute_review"]["active"] is True


def test_foreign_account_cannot_enroll_someone_else_juror_responsibility() -> None:
    st = _state()

    with pytest.raises(Exception) as exc:
        apply_tx(st, _env("ROLE_JUROR_ENROLL", "@genesis", 1, {"account_id": "@errol"}))
    assert "only_account_can_enroll_juror" in str(exc.value)
    assert "@errol" not in st["roles"]["jurors"]["by_id"]


def test_content_report_assignment_uses_opted_in_errol_and_excludes_original_poster() -> None:
    st = _state()
    apply_tx(st, _env("ROLE_JUROR_ENROLL", "@errol", 1, {"account_id": "@errol"}))
    apply_tx(st, _env("REVIEWER_LANE_OPT_IN", "@errol", 2, {"account_id": "@errol", "lane": "content_review"}))

    apply_tx(
        st,
        _env(
            "CONTENT_ESCALATE_TO_DISPUTE",
            "SYSTEM",
            4,
            {
                "target_type": "content",
                "target_id": "post:@genesis:1",
                "reason": "policy",
                "reported_by": "@errol",
            },
            system=True,
        ),
    )

    dispute = next(iter(st["disputes_by_id"].values()))
    assert dispute["reviewer_responsibility_policy"] == "explicit_active_juror_opt_in_required"
    assert dispute["target_owner"] == "@genesis"
    assert dispute["assigned_jurors"] == ["@errol"]
    assert "@genesis" not in dispute["assigned_jurors"]
