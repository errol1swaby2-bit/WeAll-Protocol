from __future__ import annotations

from weall.runtime.domain_dispatch import apply_tx
from weall.runtime.tx_admission import TxEnvelope


def _state() -> dict:
    return {
        "height": 10,
        "accounts": {
            "@errol": {
                "nonce": 0,
                "poh_tier": 2,
                "banned": False,
                "locked": False,
                "reputation": 10,
            },
            "@devnet-genesis": {
                "nonce": 0,
                "poh_tier": 2,
                "banned": False,
                "locked": False,
                "reputation": 10,
            },
        },
        "roles": {"jurors": {"by_id": {}, "active_set": []}},
        "content": {
            "posts": {
                "post:@devnet-genesis:1": {
                    "id": "post:@devnet-genesis:1",
                    "author": "@devnet-genesis",
                    "body": "test",
                    "visibility": "public",
                    "deleted": False,
                    "locked": False,
                }
            },
            "comments": {},
        },
        "disputes_by_id": {
            "dispute:SYSTEM:0": {
                "dispute_id": "dispute:SYSTEM:0",
                "target_type": "content",
                "target_id": "post:@devnet-genesis:1",
                "target_owner": "@devnet-genesis",
                "stage": "unassigned",
                "assignment_blocked_reason": "no_unconflicted_content_reviewer",
                "reviewer_responsibility_policy": "explicit_active_juror_opt_in_required",
                "jurors": {},
                "eligible_juror_ids": [],
                "assigned_jurors": [],
                "eligible_validator_count": 0,
                "required_votes": 0,
            }
        },
    }


def _role_env(account: str, nonce: int = 1) -> TxEnvelope:
    return TxEnvelope(
        tx_type="REVIEWER_LANE_OPT_IN",
        signer=account,
        nonce=nonce,
        payload={"account_id": account, "lane": "content_review"},
        sig="",
        system=False,
    )


def test_reviewer_opt_in_reassigns_pending_unassigned_content_review() -> None:
    state = _state()

    result = apply_tx(state, _role_env("@errol"))

    assert result["applied"] == "REVIEWER_LANE_OPT_IN"
    assert result["reassigned_content_reviews"] == 1
    dispute = state["disputes_by_id"]["dispute:SYSTEM:0"]
    assert dispute["stage"] == "juror_review"
    assert dispute["assignment_blocked_reason"] == ""
    assert dispute["eligible_juror_ids"] == ["@errol"]
    assert dispute["assigned_jurors"] == ["@errol"]
    assert dispute["eligible_validator_count"] == 1
    assert dispute["required_votes"] == 1
    assert dispute["jurors"]["@errol"]["status"] == "assigned"
    assert dispute["jurors"]["@errol"]["assignment_source"] == "reviewer_responsibility_opt_in"


def test_target_owner_opt_in_does_not_reassign_own_content_review() -> None:
    state = _state()

    result = apply_tx(state, _role_env("@devnet-genesis"))

    assert result["applied"] == "REVIEWER_LANE_OPT_IN"
    assert result["reassigned_content_reviews"] == 0
    dispute = state["disputes_by_id"]["dispute:SYSTEM:0"]
    assert dispute["stage"] == "unassigned"
    assert dispute["assigned_jurors"] == []
    assert dispute["jurors"] == {}
    assert dispute["assignment_blocked_reason"] == "target_owner_cannot_review_own_content"
