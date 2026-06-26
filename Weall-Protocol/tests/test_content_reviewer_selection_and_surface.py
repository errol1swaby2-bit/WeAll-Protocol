from __future__ import annotations

from pathlib import Path

from weall.runtime.domain_dispatch import apply_tx
from weall.runtime.tx_admission import TxEnvelope

ROOT = Path(__file__).resolve().parents[1]
OUTER = ROOT.parent


def _env(tx_type: str, signer: str, nonce: int, payload: dict, *, system: bool = False) -> TxEnvelope:
    return TxEnvelope(tx_type=tx_type, signer=signer, nonce=nonce, payload=payload, sig="", system=system)


def _two_account_state() -> dict:
    return {
        "height": 10,
        "accounts": {
            "@genesis": {"nonce": 0, "poh_tier": 2, "banned": False, "locked": False, "reputation_milli": 6000},
            "@errol": {"nonce": 0, "poh_tier": 2, "banned": False, "locked": False, "reputation_milli": 6000},
        },
        "roles": {
            "validators": {"active_set": ["@genesis"]},
            "jurors": {"active_set": [], "by_id": {}},
        },
        "content": {
            "posts": {
                "post:@genesis:1": {
                    "id": "post:@genesis:1",
                    "post_id": "post:@genesis:1",
                    "author": "@genesis",
                    "body": "reported genesis content",
                    "visibility": "public",
                    "deleted": False,
                    "locked": False,
                    "labels": [],
                    "flags": [],
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


def test_content_review_selection_requires_exact_content_review_lane_not_generic_juror() -> None:
    state = _two_account_state()

    # ROLE_JUROR_ENROLL activates the coarse juror role, but with exact-lane
    # policy it must not make the account selectable for content reports until
    # content_review is explicitly opted in.
    apply_tx(state, _env("ROLE_JUROR_ENROLL", "@errol", 1, {"account_id": "@errol"}))
    coarse_rec = state["roles"]["jurors"]["by_id"]["@errol"]
    assert coarse_rec["active"] is True
    assert coarse_rec["responsibilities"]["reviewer"] == {}

    apply_tx(
        state,
        _env(
            "CONTENT_ESCALATE_TO_DISPUTE",
            "SYSTEM",
            2,
            {
                "target_type": "content",
                "target_id": "post:@genesis:1",
                "reason": "policy",
                "reported_by": "@errol",
                "flagged_by": "@errol",
            },
            system=True,
        ),
    )

    dispute = next(iter(state["disputes_by_id"].values()))
    assert dispute["target_owner"] == "@genesis"
    assert dispute["stage"] == "unassigned"
    assert dispute["assignment_blocked_reason"] == "no_unconflicted_content_reviewer"
    assert dispute["assigned_jurors"] == []
    assert "@genesis" not in dispute.get("assigned_jurors", [])

    result = apply_tx(
        state,
        _env("REVIEWER_LANE_OPT_IN", "@errol", 3, {"account_id": "@errol", "lane": "content_review"}),
    )

    assert result["applied"] == "REVIEWER_LANE_OPT_IN"
    assert result["reassigned_content_reviews"] == 1
    dispute = next(iter(state["disputes_by_id"].values()))
    assert dispute["stage"] == "juror_review"
    assert dispute["assigned_jurors"] == ["@errol"]
    assert dispute["eligible_juror_ids"] == ["@errol"]
    assert dispute["jurors"]["@errol"]["assignment_source"] == "reviewer_responsibility_opt_in"
    assert "@genesis" not in dispute["assigned_jurors"]


def test_frontend_surfaces_content_review_opt_in_and_juror_review_queue_stage() -> None:
    verification_page = (OUTER / "web/src/pages/AccountVerificationPage.tsx").read_text(encoding="utf-8")
    juror_dashboard = (OUTER / "web/src/pages/JurorDashboard.tsx").read_text(encoding="utf-8")

    assert "weall.accountReviewerStatus" in verification_page
    assert "Content review selection" in verification_page
    assert "REVIEWER_LANE_OPT_IN" in verification_page
    assert "REVIEWER_LANE_OPT_OUT" in verification_page
    assert 'lane: "content_review"' in verification_page
    assert "Open all responsibility controls" in verification_page
    assert '"juror_review"' in juror_dashboard
