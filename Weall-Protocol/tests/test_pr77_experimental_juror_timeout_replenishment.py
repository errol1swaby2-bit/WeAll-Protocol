"""Time-based substitute promotion / reserve backfill on exact block heights."""

from __future__ import annotations

import copy

import pytest

from weall.runtime.dispute_engine import tick_dispute_lifecycle


def _role() -> dict:
    return {"active": True, "responsibilities": {
        "reviewer": {"dispute_review": {"active": True, "opted_in": True}}
    }}


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
        case.update({
            "original_panel_juror_ids": original,
            "original_substitute_juror_ids": original_reserve,
            "appeal_panel_juror_ids": list(second),
            "appeal_substitute_juror_ids": list(second_reserve),
            "appeal_panel_round": 2,
            "appeal_panel_status": "assigned",
            "appeal_panel_commitment": "original-fresh-panel-commitment",
        })
    return {
        "chain_id": "replenishment-fixture",
        "height": 10,
        "params": {
            "m3_civic_governance_strict": True,
            "experimental_severe_juror_replenishment_v0": enabled,
            "dispute": {"experimental_juror_response_window_blocks": 3},
        },
        "meta": {"constitutional_clock": {"enabled": True}},
        "roles": {"jurors": {
            "active_set": everyone,
            "by_id": {j: _role() for j in everyone},
        }},
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
        case["original_panel_juror_ids"] + case["original_substitute_juror_ids"]
        + case["appeal_panel_juror_ids"] + case["appeal_substitute_juror_ids"]
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
