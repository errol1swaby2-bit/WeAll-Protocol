"""Time-based substitute promotion / reserve backfill on exact block heights."""

from __future__ import annotations

import copy

import pytest

from weall.runtime.dispute_engine import tick_dispute_lifecycle


def _role() -> dict:
    return {
        "active": True,
        "responsibilities": {"reviewer": {"dispute_review": {"active": True, "opted_in": True}}},
    }


def _state(*, appeal: bool = True, enabled: bool = True, reviewers: int = 90) -> dict:
    everyone = [f"@juror-{i:03d}" for i in range(reviewers)]
    original = everyone[:25]
    original_reserve = everyone[25:30]
    second = everyone[30:55] if appeal else original
    second_reserve = everyone[55:60] if appeal else original_reserve
    stage = "appeal_review" if appeal else "juror_review"
    case = {
        "id": "case",
        "target_type": "account",
        "target_id": "@target",
        "sanction_class": "S4",
        "severity": "severe",
        "stage": stage,
        "panel_status": "assigned",
        "panel_round": 1,
        "panel_commitment": "original-panel-commitment",
        "assigned_jurors": list(second),
        "substitute_juror_ids": list(original_reserve),
        "eligible_juror_ids": list(second),
        "required_votes": 20,
        "resolved": bool(appeal),
        "jurors": {
            juror: {
                "status": "assigned" if index == 0 else "accepted",
                "assigned_at_height": 10,
                "vote_deadline_height": 200,
                "panel_round": 2 if appeal else 1,
            }
            for index, juror in enumerate(second)
        },
        "vote_counts": {},
        "voted_juror_ids": [],
        "ballot_nullifiers": {},
        "appeal_vote_counts": {},
        "appeal_voted_juror_ids": [],
        "appeal_ballot_nullifiers": {},
    }
    if appeal:
        case.update(
            {
                "original_panel_juror_ids": original,
                "original_substitute_juror_ids": original_reserve,
                "appeal_panel_juror_ids": list(second),
                "appeal_substitute_juror_ids": list(second_reserve),
                "appeal_panel_round": 2,
                "appeal_panel_status": "assigned",
                "appeal_panel_commitment": "original-fresh-panel-commitment",
            }
        )
    return {
        "chain_id": "replenishment-fixture",
        "height": 10,
        "params": {
            "m3_civic_governance_strict": True,
            "experimental_severe_juror_replenishment_v0": enabled,
            "dispute": {"experimental_juror_response_window_blocks": 3},
        },
        "meta": {"constitutional_clock": {"enabled": True}},
        "roles": {
            "jurors": {
                "active_set": everyone,
                "by_id": {j: _role() for j in everyone},
            }
        },
        "accounts": {
            **{j: {"poh_tier": 2, "banned": False, "locked": False} for j in everyone},
            "@target": {"poh_tier": 2, "banned": False, "locked": False},
        },
        "disputes_by_id": {"case": case},
        "system_queue": [],
    }


@pytest.mark.parametrize("appeal", [False, True], ids=["initial", "fresh-appeal"])
def test_no_response_promotes_substitute_and_refills_reserve(appeal: bool) -> None:
    state = _state(appeal=appeal)
    prior = copy.deepcopy(state)
    case = state["disputes_by_id"]["case"]
    outgoing = case["assigned_jurors"][0]
    reserve_key = "appeal_substitute_juror_ids" if appeal else "substitute_juror_ids"
    incoming = case[reserve_key][0]
    assert tick_dispute_lifecycle(state, next_height=13) == 0
    assert state == prior
    assert tick_dispute_lifecycle(state, next_height=14) == 0
    case = state["disputes_by_id"]["case"]
    assert case["assigned_jurors"][0] == incoming
    assert len(case["assigned_jurors"]) == 25
    assert len(case[reserve_key]) == 5
    assert incoming not in case[reserve_key]
    assert outgoing not in case["assigned_jurors"]
    assert case["jurors"][outgoing]["status"] == "replaced_no_response"
    assert case["jurors"][incoming]["assigned_at_height"] == 14
    assert case["required_votes"] == 20
    assert len(case["experimental_juror_replacements"]) == 1
    assert not state["system_queue"]
    assert "reputation" not in state
    replica = copy.deepcopy(prior)
    assert tick_dispute_lifecycle(replica, next_height=14) == 0
    assert replica == state


def test_timeout_receipt_status_promotes_only_after_canonical_timeout() -> None:
    state = _state()
    case = state["disputes_by_id"]["case"]
    old = case["assigned_jurors"][1]
    case["jurors"][old]["status"] = "accepted"
    case["jurors"][old]["vote_deadline_height"] = 12
    before = copy.deepcopy(state)
    # Scheduler must not displace an accepted juror until the SYSTEM timeout
    # receipt actually marks the juror timed_out.
    tick_dispute_lifecycle(state, next_height=13)
    assert state["disputes_by_id"]["case"]["assigned_jurors"][1] == old
    assert any(item["tx_type"] == "DISPUTE_JUROR_TIMEOUT" for item in state["system_queue"])
    assert state["disputes_by_id"]["case"]["jurors"][old]["status"] == "accepted"
    state = copy.deepcopy(before)
    case = state["disputes_by_id"]["case"]
    case["jurors"][old]["status"] = "timed_out"
    tick_dispute_lifecycle(state, next_height=13)
    assert case["assigned_jurors"][1] != old
    assert case["jurors"][old]["status"] == "timed_out"


def test_recorded_ballot_juror_is_not_replaced() -> None:
    state = _state()
    case = state["disputes_by_id"]["case"]
    who = case["assigned_jurors"][1]
    case["jurors"][who]["status"] = "timed_out"
    case["appeal_voted_juror_ids"] = [who]
    case["appeal_vote_counts"] = {"uphold": 1}
    case["appeal_ballot_nullifiers"] = {"synthetic-nullifier": {"final": True}}
    tick_dispute_lifecycle(state, next_height=14)
    assert case["assigned_jurors"][1] == who


def test_no_reviewer_available_for_reserve_backfill_is_fail_closed() -> None:
    state = _state(reviewers=60)
    before = copy.deepcopy(state)
    tick_dispute_lifecycle(state, next_height=14)
    assert state == before


@pytest.mark.parametrize("value", [False, None, "true", 1])
def test_default_off_never_replaces(value) -> None:
    state = _state(enabled=False)
    state["params"]["experimental_severe_juror_replenishment_v0"] = value
    before = copy.deepcopy(state)
    tick_dispute_lifecycle(state, next_height=14)
    assert state == before


def test_fresh_appeal_never_reuses_original_juror() -> None:
    state = _state()
    case = state["disputes_by_id"]["case"]
    tick_dispute_lifecycle(state, next_height=14)
    all_identities = (
        case["original_panel_juror_ids"]
        + case["original_substitute_juror_ids"]
        + case["appeal_panel_juror_ids"]
        + case["appeal_substitute_juror_ids"]
    )
    assert len(all_identities) == len(set(all_identities)) == 60


def test_repeat_tick_at_same_height_does_not_reuse_replaced_juror() -> None:
    state = _state()
    tick_dispute_lifecycle(state, next_height=14)
    previous = copy.deepcopy(state)
    tick_dispute_lifecycle(state, next_height=14)
    assert state == previous


@pytest.mark.parametrize("status", ["declined", "withdrawn", "timed_out"])
def test_existing_nonparticipant_status_promotes_without_deadline(status) -> None:
    state = _state()
    case = state["disputes_by_id"]["case"]
    case["jurors"][case["assigned_jurors"][1]]["status"] = status
    tick_dispute_lifecycle(state, next_height=11)
    assert case["experimental_juror_replacements"][0]["reason"] == status
    assert case["required_votes"] == 20


@pytest.mark.parametrize("source", ["case", "rules", "reporter", "target"])
def test_newly_conflicted_reserve_cannot_be_promoted(source: str) -> None:
    state = _state()
    case = state["disputes_by_id"]["case"]
    incoming = case["appeal_substitute_juror_ids"][0]
    if source == "case":
        case["conflicted_account_ids"] = [incoming]
    elif source == "rules":
        case["rules"] = {"conflicted_account_ids": [incoming]}
    elif source == "reporter":
        case["reported_by"] = incoming
    else:
        case["appeal_substitute_juror_ids"][0] = "@target"
    before = copy.deepcopy(state)
    assert tick_dispute_lifecycle(state, next_height=14) == 0
    assert state == before


def test_historical_retired_juror_cannot_be_promoted_from_reserve() -> None:
    state = _state()
    case = state["disputes_by_id"]["case"]
    retired = "@juror-061"
    case["appeal_substitute_juror_ids"][0] = retired
    case["experimental_juror_replacements"] = [{"outgoing": retired, "reason": "timed_out"}]
    before = copy.deepcopy(state)
    assert tick_dispute_lifecycle(state, next_height=14) == 0
    assert state == before


def test_previously_assigned_juror_cannot_be_reintroduced_as_reserve() -> None:
    state = _state()
    case = state["disputes_by_id"]["case"]
    former = "@juror-061"
    case["appeal_substitute_juror_ids"][0] = former
    case["jurors"][former] = {"status": "timed_out", "panel_round": 2}
    before = copy.deepcopy(state)
    assert tick_dispute_lifecycle(state, next_height=14) == 0
    assert state == before


def _general_state(
    *, size: int, appeal: bool, general: bool = True, reviewers: int = 100
) -> dict:
    """Derive 7/15/ordinary-25 cases from the existing review-role fixture."""
    from weall.runtime.bft_hotstuff import quorum_threshold

    state = _state(appeal=False, enabled=False, reviewers=reviewers)
    roster = [f"@juror-{i:03d}" for i in range(reviewers)]
    reserve_size = (size + 4) // 5
    old_panel = roster[:size]
    old_reserve = roster[size : size + reserve_size]
    second_start = size + reserve_size
    panel = roster[second_start : second_start + size] if appeal else old_panel
    reserve = (
        roster[second_start + size : second_start + size + reserve_size]
        if appeal
        else old_reserve
    )
    case = state["disputes_by_id"]["case"]
    case["severity"] = {7: "low", 15: "medium", 25: "high"}[size]
    case["sanction_class"] = ""
    case["stage"] = "appeal_review" if appeal else "juror_review"
    case["resolved"] = appeal
    case["assigned_jurors"] = list(panel)
    case["eligible_juror_ids"] = list(panel)
    case["substitute_juror_ids"] = list(old_reserve)
    case["panel_round"] = 1
    case["required_votes"] = quorum_threshold(size)
    case["jurors"] = {
        juror: {
            "status": "assigned" if idx == 0 else "accepted",
            "assigned_at_height": 10,
            "vote_deadline_height": 200,
            "panel_round": 2 if appeal else 1,
        }
        for idx, juror in enumerate(panel)
    }
    if appeal:
        case.update(
            original_panel_juror_ids=list(old_panel),
            original_substitute_juror_ids=list(old_reserve),
            appeal_panel_juror_ids=list(panel),
            appeal_substitute_juror_ids=list(reserve),
            appeal_panel_round=2,
            appeal_panel_status="assigned",
            appeal_panel_commitment="unchanged-appeal-commitment",
        )
    state["params"]["experimental_general_juror_replenishment_v0"] = general
    return state


@pytest.mark.parametrize("size", [7, 15, 25])
@pytest.mark.parametrize("appeal", [False, True])
def test_general_panels_reuse_fifo_promotion_and_backfill(
    size: int, appeal: bool
) -> None:
    from weall.runtime.bft_hotstuff import quorum_threshold

    state = _general_state(size=size, appeal=appeal)
    before = copy.deepcopy(state)
    case = state["disputes_by_id"]["case"]
    outgoing = case["assigned_jurors"][0]
    reserve_key = "appeal_substitute_juror_ids" if appeal else "substitute_juror_ids"
    incoming = case[reserve_key][0]
    assert tick_dispute_lifecycle(state, next_height=13) == 0
    assert state == before
    assert tick_dispute_lifecycle(state, next_height=14) == 0
    assert case["assigned_jurors"][0] == incoming
    assert len(case["assigned_jurors"]) == size
    assert len(case[reserve_key]) == (size + 4) // 5
    assert case["required_votes"] == quorum_threshold(size)
    assert case["jurors"][outgoing]["status"] == "replaced_no_response"
    assert len(case["experimental_juror_replacements"]) == 1
    if appeal:
        all_jurors = (
            case["original_panel_juror_ids"]
            + case["original_substitute_juror_ids"]
            + case["appeal_panel_juror_ids"]
            + case["appeal_substitute_juror_ids"]
        )
        assert len({_j.removeprefix("@") for _j in all_jurors}) == len(all_jurors)
    replica = copy.deepcopy(before)
    tick_dispute_lifecycle(replica, next_height=14)
    assert replica == state
    again = copy.deepcopy(state)
    tick_dispute_lifecycle(state, next_height=14)
    assert again == state


@pytest.mark.parametrize("size", [7, 15, 25])
def test_general_accepted_nonvoter_needs_canonical_timeout(size: int) -> None:
    state = _general_state(size=size, appeal=False)
    case = state["disputes_by_id"]["case"]
    juror = case["assigned_jurors"][0]
    case["jurors"][juror]["status"] = "accepted"
    case["jurors"][juror]["vote_deadline_height"] = 12
    tick_dispute_lifecycle(state, next_height=13)
    assert case["assigned_jurors"][0] == juror
    assert any(q["tx_type"] == "DISPUTE_JUROR_TIMEOUT" for q in state["system_queue"])
    # The scheduler does not forge or shortcut the canonical receipt.
    state["system_queue"].clear()
    case["jurors"][juror]["status"] = "timed_out"
    tick_dispute_lifecycle(state, next_height=13)
    assert case["assigned_jurors"][0] != juror


@pytest.mark.parametrize("size", [7, 15, 25])
def test_general_juror_with_recorded_ballot_is_never_replaced(size: int) -> None:
    state = _general_state(size=size, appeal=False)
    case = state["disputes_by_id"]["case"]
    juror = case["assigned_jurors"][0]
    case["jurors"][juror]["status"] = "timed_out"
    case["voted_juror_ids"] = [juror]
    case["vote_counts"] = {"yes": 1}
    case["ballot_nullifiers"] = {"synthetic-final-nullifier": {"final": True}}
    tick_dispute_lifecycle(state, next_height=14)
    assert case["assigned_jurors"][0] == juror


@pytest.mark.parametrize("size", [7, 15, 25])
def test_general_pool_missing_replacement_refill_remains_unchanged(size: int) -> None:
    reserve_size = (size + 4) // 5
    state = _general_state(
        size=size, appeal=False, reviewers=size + reserve_size
    )
    prior = copy.deepcopy(state)
    tick_dispute_lifecycle(state, next_height=14)
    assert state == prior


@pytest.mark.parametrize("size", [7, 15, 25])
def test_general_switch_is_strict_boolean_and_independent(size: int) -> None:
    state = _general_state(size=size, appeal=False, general=False)
    state["params"]["experimental_general_juror_replenishment_v0"] = "true"
    state["params"]["experimental_severe_juror_replenishment_v0"] = True
    before = copy.deepcopy(state)
    tick_dispute_lifecycle(state, next_height=14)
    assert state == before


def test_general_enable_does_not_enable_severe_sanctions() -> None:
    state = _state(appeal=False, enabled=False)
    state["params"]["experimental_general_juror_replenishment_v0"] = True
    prior = copy.deepcopy(state)
    tick_dispute_lifecycle(state, next_height=14)
    assert state == prior


@pytest.mark.parametrize("size", [7, 15])
def test_general_conflicted_reserve_is_not_promoted(size: int) -> None:
    state = _general_state(size=size, appeal=False)
    case = state["disputes_by_id"]["case"]
    case["conflicted_account_ids"] = [case["substitute_juror_ids"][0]]
    before = copy.deepcopy(state)
    tick_dispute_lifecycle(state, next_height=14)
    assert state == before


def test_general_content_dispute_respects_dispute_reviewer_opt_in() -> None:
    state = _general_state(size=7, appeal=False)
    case = state["disputes_by_id"]["case"]
    case["target_type"] = "content"
    reserve = case["substitute_juror_ids"][0]
    state["roles"]["jurors"]["by_id"][reserve]["responsibilities"]["reviewer"][
        "dispute_review"
    ]["opted_in"] = False
    before = copy.deepcopy(state)
    tick_dispute_lifecycle(state, next_height=14)
    assert state == before
