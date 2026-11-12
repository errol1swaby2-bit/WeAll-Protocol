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


@pytest.mark.parametrize(
    "gate_version, expected",
    ((1, 4), (2, 5), (3, 4), ("2", 4), (True, 4)),
)
def test_proposed_fixed_quorum_is_explicit_v2_only(
    panel_state: dict, monkeypatch: pytest.MonkeyPatch, gate_version: object, expected: int
) -> None:
    from weall.runtime.apply import dispute

    monkeypatch.setattr(dispute, "strict_civic_governance_enabled", lambda _state: True)
    panel_state["params"]["dispute_material_conflict_gate_version"] = gate_version
    assert (
        dispute._strict_v2_initial_panel_votes(
            panel_state, panel_state["disputes_by_id"]["case"], 6
        )
        == expected
    )


def test_proposed_fixed_quorum_does_not_reinterpret_appeal_stage(
    panel_state: dict, monkeypatch: pytest.MonkeyPatch
) -> None:
    from weall.runtime.apply import dispute

    monkeypatch.setattr(dispute, "strict_civic_governance_enabled", lambda _state: True)
    case = panel_state["disputes_by_id"]["case"]
    case["stage"] = "appeal_review"
    assert dispute._strict_v2_initial_panel_votes(panel_state, case, 6) == 4


def test_explicit_severe_constitutional_panel_preserves_twenty_vote_floor(
    panel_state: dict, monkeypatch: pytest.MonkeyPatch
) -> None:
    from weall.runtime.apply import dispute

    monkeypatch.setattr(dispute, "strict_civic_governance_enabled", lambda _state: True)
    monkeypatch.setattr(dispute, "_constitutional_clock_enabled", lambda _state: True)
    monkeypatch.setattr(dispute, "is_explicit_severe_account_sanction", lambda _case: True)
    case = panel_state["disputes_by_id"]["case"]
    assert dispute._strict_v2_initial_panel_votes(panel_state, case, 24) >= 20


def test_incomplete_strict_panel_cannot_masquerade_as_full_eligible_panel(
    panel_state: dict, monkeypatch: pytest.MonkeyPatch
) -> None:
    from weall.runtime.apply import dispute

    monkeypatch.setattr(dispute, "strict_civic_governance_enabled", lambda _state: True)
    monkeypatch.setattr(
        dispute,
        "reviewer_lane_active",
        lambda state, account, _lane: account in state["active_reviewers"],
    )
    case = panel_state["disputes_by_id"]["case"]
    eligible = list(case["assigned_jurors"])
    assert dispute._strict_v2_initial_panel_complete(panel_state, case, eligible) is False
    case["material_connection_ids"] = []
    assert dispute._strict_v2_initial_panel_complete(panel_state, case, eligible) is True
    case["assigned_jurors"][1] = "juror-0"
    assert dispute._strict_v2_initial_panel_complete(panel_state, case, eligible) is False


def test_conflicted_assigned_juror_has_unresolved_final_receipt_accountability_risk(
    panel_state: dict,
) -> None:
    risk = _check_pure(panel_state)["currently_impacted_juror_reputation_risks"]
    assert len(risk) == 1
    assert risk[0]["juror"] == "@juror-0"
    assert risk[0]["status"] == "assigned"
    assert risk[0]["final_receipt_missed_vote_flag_exposure"] is True
    assert risk[0]["late_withdraw_penalty_exposure"] is False
    assert risk[0]["timeout_penalty_exposure"] is False
    assert risk[0]["conflict_introduction_height_verified"] is False
    assert risk[0]["actual_penalty_or_suspension_proven"] is False
    assert risk[0]["penalty_waiver_authorized"] is False


@pytest.mark.parametrize("height,late,timeout", ((9, False, False), (11, True, False), (21, True, True)))
def test_conflicted_accepted_juror_deadline_penalty_exposures_are_height_bound(
    panel_state: dict, height: int, late: bool, timeout: bool
) -> None:
    panel_state["height"] = height
    panel_state["disputes_by_id"]["case"]["jurors"]["@juror-0"] = {
        "status": "accepted",
        "accepted_at_height": 1,
        "safe_withdraw_until_height": 10,
        "vote_deadline_height": 20,
        "reputation_policy": {
            "late_withdraw_penalty_milli": -501,
            "timeout_penalty_milli": -1501,
        },
    }
    risk = _check_pure(panel_state)["currently_impacted_juror_reputation_risks"][0]
    assert risk["late_withdraw_penalty_exposure"] is late
    assert risk["timeout_penalty_exposure"] is timeout
    assert risk["late_withdraw_penalty_milli_if_applied"] == -501
    assert risk["timeout_penalty_milli_if_applied"] == -1501
    assert risk["current_height"] == height
    assert risk["final_receipt_missed_vote_flag_exposure"] is True


def test_committed_ballot_prevents_missed_vote_and_timeout_exposure(panel_state: dict) -> None:
    panel_state["height"] = 21
    case = panel_state["disputes_by_id"]["case"]
    case["jurors"]["@juror-0"] = {
        "status": "completed",
        "safe_withdraw_until_height": 10,
        "vote_deadline_height": 20,
    }
    case["voted_juror_ids"] = ["juror-0"]
    risk = _check_pure(panel_state)["currently_impacted_juror_reputation_risks"][0]
    assert risk["ballot_already_submitted"] is True
    assert risk["late_withdraw_penalty_exposure"] is False
    assert risk["timeout_penalty_exposure"] is False
    assert risk["final_receipt_missed_vote_flag_exposure"] is False


@pytest.mark.parametrize("terminal", ("withdrawn", "declined", "timed_out"))
def test_existing_final_accountability_skip_status_preserved(
    panel_state: dict, terminal: str
) -> None:
    panel_state["disputes_by_id"]["case"]["jurors"]["@juror-0"] = {"status": terminal}
    risk = _check_pure(panel_state)["currently_impacted_juror_reputation_risks"][0]
    assert risk["final_receipt_missed_vote_flag_exposure"] is False
    assert risk["penalty_waiver_authorized"] is False


def test_preview_does_not_infer_expiry_from_unverified_block_height(panel_state: dict) -> None:
    case = panel_state["disputes_by_id"]["case"]
    case["jurors"]["@juror-0"] = {
        "status": "accepted",
        "safe_withdraw_until_height": 10,
        "vote_deadline_height": 20,
    }
    panel_state["height"] = "100"
    risk = _check_pure(panel_state)["currently_impacted_juror_reputation_risks"][0]
    assert risk["current_height"] is None
    assert risk["safe_withdraw_window_expired"] is None
    assert risk["vote_deadline_expired"] is None
    assert risk["timeout_penalty_exposure"] is False


def test_duplicate_juror_record_aliases_cannot_be_accepted_as_unambiguous(
    panel_state: dict,
) -> None:
    case = panel_state["disputes_by_id"]["case"]
    case["jurors"]["juror-0"] = {"status": "accepted"}
    risk = _check_pure(panel_state)["currently_impacted_juror_reputation_risks"][0]
    assert risk["juror_record_unambiguous"] is False
    assert risk["actual_penalty_or_suspension_proven"] is False
