"""PR77 adversarial, non-authoritative deterministic appeal preview tests."""

from __future__ import annotations

import copy

import pytest

from weall.runtime.apply.dispute import select_dispute_panel
from weall.runtime.severe_appeal_candidate import preview_fresh_severe_appeal


def _state(*, cls: str = "S4", reviewers: int = 95) -> dict:
    roster = [f"juror-{i:03d}" for i in range(reviewers)]
    dispute = {
        "id": "d-severe",
        "target_type": "account",
        "target_id": "@target",
        "sanction_class": cls,
        "severity": "low",
        "rules": {"sanction_class": cls, "severity": "severe"},
        "panel_status": "assigned",
        "panel_commitment": "initial-unverified-commitment",
        "assigned_jurors": roster[:25],
        "substitute_juror_ids": roster[25:30],
        "vote_counts": {"yes": 20, "no": 5},
        "resolved": True,
        "resolution": {"outcome": "report_upheld"},
        "stage": "appeal_window",
        "opened_at_height": 4,
    }
    return {
        "chain_id": "candidate-test-chain",
        "height": 15,
        "meta": {"constitutional_clock": {"enabled": True}},
        "params": {"m3_civic_governance_strict": True},
        "roles": {"jurors": {"active_set": roster}},
        "disputes_by_id": {"d-severe": dispute},
    }


def _preview(state: dict) -> dict:
    return preview_fresh_severe_appeal(state, dispute_id="d-severe")


def test_s4_requires_twenty_five_and_five_even_with_outer_low() -> None:
    state = _state()
    case = state["disputes_by_id"]["d-severe"]
    result = select_dispute_panel(
        copy.deepcopy(state),
        copy.deepcopy(case),
        state["roles"]["jurors"]["active_set"],
        round_no=1,
    )
    assert result["required_panel_size"] == 25
    assert result["required_substitute_count"] == 5


def test_complete_fresh_panel_preview_is_still_not_authorization() -> None:
    state = _state()
    original = copy.deepcopy(state)
    result = _preview(state)
    assert result["candidate_panel_complete"] is True
    assert result["status"] == "BLOCKED_REVIEW_ONLY"
    assert len(result["panel"]) == 25
    assert len(result["substitutes"]) == 5
    assert set(result["panel"] + result["substitutes"]).isdisjoint(
        state["disputes_by_id"]["d-severe"]["assigned_jurors"]
        + state["disputes_by_id"]["d-severe"]["substitute_juror_ids"]
    )
    assert result["may_enqueue_account_ban"] is False
    assert result["may_finalize_severe_sanction"] is False
    assert result["authorization_blockers"]
    assert state == original


def test_roster_is_deterministic_and_state_independent() -> None:
    state = _state()
    assert _preview(state) == _preview(copy.deepcopy(state))
    assert _preview(state) == _preview(state)


@pytest.mark.parametrize("yes", [0, 17, 19, True, "20", 26])
def test_insufficient_or_malformed_yes_never_produces_roster(yes) -> None:
    state = _state()
    state["disputes_by_id"]["d-severe"]["vote_counts"]["yes"] = yes
    result = _preview(state)
    assert not result["candidate_panel_complete"]
    assert not result["panel"]
    assert not result["may_enqueue_account_ban"]


def test_insufficient_fresh_reviewers_fails_closed() -> None:
    result = _preview(_state(reviewers=58))
    assert not result["candidate_panel_complete"]
    assert "fresh_appeal_pool_incomplete_or_not_independent" in result["structural_blockers"]


def test_missing_original_substitutes_fails_closed() -> None:
    state = _state()
    state["disputes_by_id"]["d-severe"]["substitute_juror_ids"] = []
    assert "initial_substitutes_not_5_distinct" in _preview(state)["structural_blockers"]


def test_alias_duplicate_initial_panel_fails_closed() -> None:
    state = _state()
    panel = state["disputes_by_id"]["d-severe"]["assigned_jurors"]
    panel[-1] = "@" + panel[0]
    assert "initial_panel_not_25_distinct" in _preview(state)["structural_blockers"]


def test_conflicting_original_and_substitute_fails_closed() -> None:
    state = _state()
    state["disputes_by_id"]["d-severe"]["substitute_juror_ids"][0] = "juror-000"
    assert "initial_panel_substitute_overlap" in _preview(state)["structural_blockers"]


def test_non_strict_clock_mode_fails_closed() -> None:
    state = _state()
    state["params"]["m3_civic_governance_strict"] = False
    assert "strict_civic_profile_not_active" in _preview(state)["structural_blockers"]


def test_disabled_clock_fails_closed() -> None:
    state = _state()
    state["meta"]["constitutional_clock"]["enabled"] = False
    assert "constitutional_clock_not_active" in _preview(state)["structural_blockers"]


def test_missing_case_fails_closed() -> None:
    state = _state()
    state["disputes_by_id"] = {}
    assert "dispute_not_found" in _preview(state)["structural_blockers"]


def test_no_s4_or_severe_marker_fails_closed() -> None:
    state = _state()
    case = state["disputes_by_id"]["d-severe"]
    case["sanction_class"] = "S2"
    case["severity"] = "low"
    case["rules"] = {}
    assert "canonical_severe_account_class_not_established" in _preview(state)[
        "structural_blockers"
    ]


def test_forged_receipt_fields_do_not_authorize_candidate() -> None:
    state = _state()
    state["disputes_by_id"]["d-severe"]["appeal_panel_result"] = {
        "decision": "uphold",
        "reached": True,
        "counts": {"uphold": 25},
    }
    result = _preview(state)
    assert result["may_enqueue_account_ban"] is False
    assert result["may_finalize_severe_sanction"] is False
