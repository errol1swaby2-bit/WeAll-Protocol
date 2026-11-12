"""PR88 unactivated dispute-panel recusal/substitute diagnostics.

All states here are synthetic, and the preview is read-only. Tests do not
authorize a new quorum, appointment, reputation penalty or governance upgrade.
The separate signed replay test exercises this preview against real committed
development-chain transactions.
"""

from __future__ import annotations

from copy import deepcopy

import pytest

from weall.runtime import dispute_panel_recovery_preview as preview


@pytest.fixture
def panel_state(monkeypatch: pytest.MonkeyPatch) -> dict:
    monkeypatch.setattr(preview, "strict_civic_governance_enabled", lambda _state: True)
    monkeypatch.setattr(
        preview,
        "reviewer_lane_active",
        lambda state, account, _lane: account in state["active_reviewers"],
    )
    jurors = [f"@juror-{index}" for index in range(7)]
    substitutes = ["@substitute-z", "@substitute-a"]
    case = {
        "id": "case",
        "target_type": "group",
        "target_id": "group",
        "opened_by": "@reporter",
        "stage": "juror_review",
        "panel_status": "assigned",
        "panel_round": 1,
        "panel_commitment": "a" * 64,
        "panel_required_size": 7,
        "substitute_required_count": 2,
        "assigned_jurors": jurors,
        "substitute_juror_ids": substitutes,
        "eligible_juror_ids": jurors[:],
        "eligible_validator_count": 7,
        "required_votes": 5,
        "jurors": {account: {"status": "assigned"} for account in jurors},
        "votes": {},
        "voted_juror_ids": [],
        "vote_counts": {},
        "material_connection_ids": ["@juror-0"],
    }
    return {
        "chain_id": "weall-test",
        "params": {"dispute_material_conflict_gate_version": 2},
        "active_reviewers": jurors + substitutes,
        "roles": {"groups_by_id": {"group": {"moderators": ["@reporter"]}}},
        "disputes_by_id": {"case": case},
    }


def _check_pure(state: dict) -> dict:
    before = deepcopy(state)
    result = preview.preview_dispute_panel_recovery(state, "case")
    assert state == before
    assert preview.preview_dispute_panel_recovery(deepcopy(state), "case") == result
    assert result["authorized"] is False
    assert result["automatic_reassignment_enabled"] is False
    assert result["reputation_penalty_waiver_authorized"] is False
    assert result["original_commitment_provenance_verified"] is False
    return result


def test_one_new_material_conflict_preserves_panel_and_uses_committed_reserve_order(
    panel_state: dict,
) -> None:
    result = _check_pure(panel_state)
    assert result["status"] == "candidate_requires_constitutional_review"
    assert result["required_panel_size"] == 7
    assert result["pinned_required_votes"] == 5
    assert result["minimum_required_votes"] == 5
    assert result["conflicted_assigned_jurors"] == ["@juror-0"]
    assert result["replacement_candidates"] == [
        {"original": "@juror-0", "candidate_substitute": "@substitute-z"}
    ]
    assert result["original_substitutes"] == ["@substitute-z", "@substitute-a"]
    assert result["remaining_eligible_reserves"] == 1
    assert result["reserve_replenishment_required"] == 1
    assert result["unfilled_slots"] == 0


def test_two_conflicts_use_exact_committed_reserve_order(panel_state: dict) -> None:
    panel_state["disputes_by_id"]["case"]["material_connection_ids"].append("@juror-1")
    result = _check_pure(panel_state)
    assert result["status"] == "candidate_requires_constitutional_review"
    assert result["replacement_candidates"] == [
        {"original": "@juror-0", "candidate_substitute": "@substitute-z"},
        {"original": "@juror-1", "candidate_substitute": "@substitute-a"},
    ]
    assert result["reserve_replenishment_required"] == 2
    assert result["pinned_required_votes"] == 5


def test_new_conflicts_exceeding_two_substitutes_fail_closed(panel_state: dict) -> None:
    panel_state["disputes_by_id"]["case"]["material_connection_ids"].extend(
        ["@juror-1", "@juror-2"]
    )
    result = _check_pure(panel_state)
    assert result["status"] == "blocked_insufficient_substitutes"
    assert result["unfilled_slots"] == 1
    assert result["pinned_required_votes"] == 5
    assert panel_state["disputes_by_id"]["case"]["required_votes"] == 5


def test_conflicted_substitute_cannot_be_promoted(panel_state: dict) -> None:
    panel_state["disputes_by_id"]["case"]["material_connection_ids"].append("@substitute-z")
    result = _check_pure(panel_state)
    assert result["status"] == "candidate_requires_constitutional_review"
    assert result["replacement_candidates"] == [
        {"original": "@juror-0", "candidate_substitute": "@substitute-a"}
    ]


def test_missing_active_substitute_blocks_recovery(panel_state: dict) -> None:
    panel_state["disputes_by_id"]["case"]["material_connection_ids"].extend(
        ["@juror-1", "@substitute-z"]
    )
    result = _check_pure(panel_state)
    assert result["status"] == "blocked_insufficient_substitutes"
    assert result["unfilled_slots"] == 1
    assert len(result["replacement_candidates"]) == 1


@pytest.mark.parametrize(
    "ballot_key, ballot_value",
    (
        ("voted_juror_ids", ["@juror-3"]),
        ("vote_counts", {"yes": 1}),
        ("ballot_nullifiers", {"one": {"choice": "yes"}}),
        ("votes", {"@juror-3": {"vote": "yes"}}),
    ),
)
def test_existing_ballots_block_automatic_recusal(
    panel_state: dict, ballot_key: str, ballot_value: object
) -> None:
    panel_state["disputes_by_id"]["case"][ballot_key] = ballot_value
    result = _check_pure(panel_state)
    assert result["status"] == "blocked_existing_ballots"
    assert result["ballots_already_present"] is True
    assert result["pinned_required_votes"] == 5


def test_unconflicted_panel_is_left_untouched(panel_state: dict) -> None:
    panel_state["disputes_by_id"]["case"]["material_connection_ids"] = []
    result = _check_pure(panel_state)
    assert result["status"] == "original_panel_unchanged"
    assert result["replacement_candidates"] == []
    assert result["reserve_replenishment_required"] == 0


@pytest.mark.parametrize("malformed", ("alias_duplicate", "panel_short", "reserve_short"))
def test_malformed_panel_snapshots_are_never_promoted(panel_state: dict, malformed: str) -> None:
    case = panel_state["disputes_by_id"]["case"]
    if malformed == "alias_duplicate":
        case["assigned_jurors"][1] = "juror-0"
    elif malformed == "panel_short":
        case["assigned_jurors"].pop()
    else:
        case["substitute_juror_ids"].pop()
    result = _check_pure(panel_state)
    assert result["status"] == "blocked_unverified_original_panel"


def test_reduced_quorum_snapshot_is_explicit_blocker(panel_state: dict) -> None:
    panel_state["disputes_by_id"]["case"]["required_votes"] = 4
    result = _check_pure(panel_state)
    assert result["status"] == "blocked_original_vote_threshold_drift"
    assert result["minimum_required_votes"] == 5


def test_original_panel_without_commitment_is_explicit_blocker(panel_state: dict) -> None:
    panel_state["disputes_by_id"]["case"]["panel_commitment"] = ""
    result = _check_pure(panel_state)
    assert result["status"] == "blocked_unverified_original_panel"


@pytest.mark.parametrize("gate_version", (1, 3, "2", True))
def test_pre_activation_or_unknown_gate_has_no_replacement_authority(
    panel_state: dict, gate_version: object
) -> None:
    panel_state["params"]["dispute_material_conflict_gate_version"] = gate_version
    result = _check_pure(panel_state)
    assert result["status"] == (
        "version2_not_activated"
        if gate_version == 1 and type(gate_version) is int
        else "blocked_unsupported_gate_version"
    )


def test_missing_dispute_never_materializes_state(panel_state: dict) -> None:
    before = deepcopy(panel_state)
    result = preview.preview_dispute_panel_recovery(panel_state, "not-there")
    assert result == {
        "status": "missing_dispute",
        "dispute_id": "not-there",
        "authorized": False,
    }
    assert panel_state == before
