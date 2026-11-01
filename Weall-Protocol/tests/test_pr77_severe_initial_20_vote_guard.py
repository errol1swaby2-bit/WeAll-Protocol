"""Fail-closed severe initial 20/25 gate, not sanction authorization."""

from __future__ import annotations

import copy

import pytest

from weall.runtime.apply import dispute
from weall.runtime.tx_admission import TxEnvelope


def _case(*, yes: int = 20, no: int = 0) -> dict:
    panel = [f"juror-{n:02d}" for n in range(25)]
    substitutes = [f"sub-{n:02d}" for n in range(5)]
    voted = panel[:yes + no]
    nullifiers = {
        dispute._dispute_ballot_nullifier(
            dispute_id="severe-1", panel_round=1, juror=juror, appeal=False
        ): {"final": True, "panel_round": 1, "height": 11}
        for juror in voted
    }
    return {
        "id": "severe-1",
        "target_type": "account",
        "target_id": "@target",
        "sanction_class": "S4",
        "severity": "low",
        "stage": "juror_review",
        "panel_status": "assigned",
        "panel_round": 1,
        "panel_commitment": "synthetic-non-authoritative",
        "assigned_jurors": panel,
        "substitute_juror_ids": substitutes,
        "eligible_juror_ids": panel,
        "required_votes": 17,
        "vote_counts": {"yes": yes, "no": no},
        "voted_juror_ids": voted,
        "ballot_nullifiers": nullifiers,
        "votes": {},
        "resolved": False,
        "jurors": {},
        "resolution": None,
    }


def _state(*, yes: int = 20, no: int = 0, clock: bool = True) -> dict:
    case = _case(yes=yes, no=no)
    return {
        "height": 11,
        "meta": {"constitutional_clock": {"enabled": clock}},
        "params": {"m3_civic_governance_strict": True},
        "roles": {
            "jurors": {"active_set": case["assigned_jurors"] + case["substitute_juror_ids"]}
        },
        "disputes_by_id": {"severe-1": case},
    }


def _resolve(state: dict, *, outcome: str = "report_upheld") -> dict:
    return dispute.apply_dispute(
        state,
        TxEnvelope(
            tx_type="DISPUTE_RESOLVE",
            signer="SYSTEM",
            nonce=12,
            system=True,
            payload={
                "dispute_id": "severe-1",
                "resolution": {"outcome": outcome, "summary": "synthetic"},
            },
        ),
    )


@pytest.mark.parametrize("yes", [0, 16, 17, 18, 19])
def test_strict_severe_under_twenty_cannot_auto_resolve_or_mutate(yes: int) -> None:
    state = _state(yes=yes)
    before = copy.deepcopy(state)
    dispute._maybe_schedule_dispute_auto_resolution(
        state, state["disputes_by_id"]["severe-1"], "severe-1",
        current_height=11, parent_ref="synthetic-parent",
    )
    assert state == before


@pytest.mark.parametrize("yes", [0, 17, 19])
def test_direct_system_resolve_under_twenty_rejected_before_mutation(yes: int) -> None:
    state = _state(yes=yes)
    before = copy.deepcopy(state)
    with pytest.raises(dispute.DisputeApplyError) as exc:
        _resolve(state)
    assert exc.value.code == "forbidden"
    assert exc.value.reason == "severe_sanction_initial_twenty_votes_unverified"
    assert state == before


def test_exact_twenty_with_consistent_strict_ballots_resolves_only_to_appeal_window() -> None:
    state = _state(yes=20)
    dispute._maybe_schedule_dispute_auto_resolution(
        state, state["disputes_by_id"]["severe-1"], "severe-1",
        current_height=11, parent_ref="synthetic-parent",
    )
    case = state["disputes_by_id"]["severe-1"]
    assert case["stage"] == "appeal_window"
    assert case["resolved"] is True
    assert case["resolution"]["outcome"] == "report_upheld"
    assert case["resolution"]["required_votes"] == 20
    assert not any(
        x.get("tx_type") in {"ACCOUNT_BAN", "DISPUTE_FINAL_RECEIPT"}
        for x in state.get("system_queue", [])
    )


@pytest.mark.parametrize("field", ["panel_status", "panel_commitment", "assigned_jurors",
                                  "substitute_juror_ids", "voted_juror_ids",
                                  "ballot_nullifiers", "vote_counts"])
def test_corrupt_vote_read_model_refuses_direct_resolution(field: str) -> None:
    state = _state()
    case = state["disputes_by_id"]["severe-1"]
    if field == "panel_status":
        case[field] = "insufficient_reviewer_pool"
    elif field == "panel_commitment":
        case[field] = ""
    elif field == "assigned_jurors":
        case[field] = case[field][:-1]
    elif field == "substitute_juror_ids":
        case[field] = [case["assigned_jurors"][0]] * 5
    elif field == "voted_juror_ids":
        case[field] = case[field][:-1]
    elif field == "ballot_nullifiers":
        case[field] = {}
    elif field == "vote_counts":
        case[field] = {"yes": True, "no": 0}
    before = copy.deepcopy(state)
    with pytest.raises(dispute.DisputeApplyError) as exc:
        _resolve(state)
    assert exc.value.reason == "severe_sanction_initial_twenty_votes_unverified"
    assert state == before


def test_system_payload_cannot_claim_rejection_over_observed_twenty_approvals() -> None:
    state = _state()
    before = copy.deepcopy(state)
    with pytest.raises(dispute.DisputeApplyError) as exc:
        _resolve(state, outcome="report_not_upheld")
    assert exc.value.reason == "severe_sanction_initial_outcome_mismatch"
    assert state == before


def test_legacy_clock_retains_existing_system_resolve_contract() -> None:
    state = _state(yes=17, clock=False)
    result = _resolve(state)
    assert result["applied"] == "DISPUTE_RESOLVE"
    assert state["disputes_by_id"]["severe-1"]["stage"] == "resolved"


def test_severe_s4_without_strict_ballot_profile_cannot_resolve() -> None:
    state = _state(yes=20)
    state["params"]["m3_civic_governance_strict"] = False
    before = copy.deepcopy(state)
    with pytest.raises(dispute.DisputeApplyError) as exc:
        _resolve(state)
    assert exc.value.reason == "severe_sanction_initial_twenty_votes_unverified"
    assert state == before


def test_duplicate_alias_juror_identity_fails_closed() -> None:
    state = _state()
    case = state["disputes_by_id"]["severe-1"]
    case["assigned_jurors"][-1] = "@" + case["assigned_jurors"][0]
    before = copy.deepcopy(state)
    with pytest.raises(dispute.DisputeApplyError):
        _resolve(state)
    assert state == before


def test_unverified_synthetic_full_case_is_still_not_account_ban_authority() -> None:
    state = _state(yes=20)
    _resolve(state)
    case = state["disputes_by_id"]["severe-1"]
    assert case["stage"] == "appeal_window"
    assert not any(x.get("tx_type") == "ACCOUNT_BAN" for x in state.get("system_queue", []))
