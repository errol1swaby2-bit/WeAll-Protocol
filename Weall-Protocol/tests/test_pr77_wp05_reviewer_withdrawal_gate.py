"""WP-05: bounded reviewer withdrawal cannot authorize an unreviewed verdict."""

from __future__ import annotations

import copy

from weall.runtime.apply.roles import (
    _reviewer_withdrawal_v1_active,
    _assign_unassigned_content_reviews_to_juror,
    _withdraw_unvoted_content_assignments,
)


def _state() -> dict:
    return {
        "height": 20,
        "params": {"reviewer_withdrawal_v1_activation_height": 20},
        "disputes_by_id": {
            "case:one": {
                "target_type": "content",
                "target_id": "post:one",
                "stage": "juror_review",
                "jurors": {"alice": {"status": "assigned"}},
                "assigned_jurors": ["alice"],
                "eligible_juror_ids": ["alice"],
                "required_votes": 1,
                "eligible_validator_count": 1,
            }
        },
    }


def test_withdrawal_requires_explicit_height_activation() -> None:
    state = _state()
    assert _reviewer_withdrawal_v1_active(state)
    state["height"] = 19
    assert not _reviewer_withdrawal_v1_active(state)
    state["params"] = {}
    assert not _reviewer_withdrawal_v1_active(state)


def test_unvoted_content_reviewer_withdrawal_preserves_threshold() -> None:
    state = _state()
    assert _withdraw_unvoted_content_assignments(state, "alice", nonce=7) == 1
    dispute = state["disputes_by_id"]["case:one"]
    assert dispute["jurors"]["alice"]["status"] == "withdrawn"
    assert dispute["stage"] == "unassigned"
    assert dispute["assignment_blocked_reason"] == "reviewer_withdrawn_pending_replacement"
    assert dispute["required_votes"] == 1
    assert dispute["eligible_validator_count"] == 0
    assert dispute["assigned_jurors"] == []
    assert dispute["eligible_juror_ids"] == []


def test_voted_assignment_remains_untouched() -> None:
    state = _state()
    dispute = state["disputes_by_id"]["case:one"]
    dispute["votes"] = {"alice": {"verdict": "uphold"}}
    before = copy.deepcopy(state)
    assert _withdraw_unvoted_content_assignments(state, "alice", nonce=7) == 0
    assert state == before


def test_strict_panel_not_mutated_by_legacy_withdrawal(monkeypatch) -> None:
    state = _state()
    before = copy.deepcopy(state)
    monkeypatch.setattr(
        "weall.runtime.apply.roles.strict_civic_governance_enabled",
        lambda _state: True,
    )
    assert _withdraw_unvoted_content_assignments(state, "alice", nonce=7) == 0
    assert state == before


def test_noncontent_dispute_untouched() -> None:
    state = _state()
    state["disputes_by_id"]["case:one"]["target_type"] = "account"
    state["disputes_by_id"]["case:one"]["target_id"] = "account:one"
    before = copy.deepcopy(state)
    assert _withdraw_unvoted_content_assignments(state, "alice", nonce=7) == 0
    assert state == before


def test_replacement_reviewer_can_reclaim_withdrawn_unvoted_case() -> None:
    state = _state()
    assert _withdraw_unvoted_content_assignments(state, "alice", nonce=7) == 1
    assert _assign_unassigned_content_reviews_to_juror(state, "bob", nonce=8) == 1
    dispute = state["disputes_by_id"]["case:one"]
    assert dispute["stage"] == "juror_review"
    assert dispute["assignment_blocked_reason"] == ""
    assert dispute["jurors"]["alice"]["status"] == "withdrawn"
    assert dispute["jurors"]["bob"]["status"] == "assigned"
    assert dispute["assigned_jurors"] == ["bob"]
    assert dispute["eligible_juror_ids"] == ["bob"]
    assert dispute["required_votes"] == 1
    assert dispute["eligible_validator_count"] == 1


def test_replacement_reviewer_cannot_be_case_reporter() -> None:
    state = _state()
    state["disputes_by_id"]["case:one"]["reported_by"] = "bob"
    assert _withdraw_unvoted_content_assignments(state, "alice", nonce=7) == 1
    assert _assign_unassigned_content_reviews_to_juror(state, "bob", nonce=8) == 0
    dispute = state["disputes_by_id"]["case:one"]
    assert dispute["stage"] == "unassigned"
    assert dispute["assignment_blocked_reason"] == "reporter_cannot_review_own_report"
    assert dispute["required_votes"] == 1
    assert dispute["jurors"]["alice"]["status"] == "withdrawn"
    assert "bob" not in dispute["jurors"]
