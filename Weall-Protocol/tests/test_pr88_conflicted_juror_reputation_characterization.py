"""PR88 direct-applier characterization of conflict-triggered juror penalties.

These fixtures are synthetic and do not authenticate an on-chain SYSTEM
timeout, a final-receipt producer, or the timing of a material conflict.
They pin current production-source behavior for constitutional review,
without authorizing a waiver, replacement, governance activation or replay edit.
"""

from __future__ import annotations

from copy import deepcopy

import pytest

from weall.runtime.apply import dispute
from weall.runtime.tx_admission_types import TxEnvelope


def _accepted_conflicted_state() -> dict:
    return {
        "height": 50,
        "params": {"dispute_material_conflict_gate_version": 2},
        "accounts": {"@juror": {}},
        "disputes_by_id": {
            "case": {
                "id": "case",
                "stage": "juror_review",
                "target_type": "group",
                "target_id": "group",
                "financial_connection_ids": ["juror"],
                "assigned_jurors": ["@juror"],
                "eligible_juror_ids": ["@juror"],
                "voted_juror_ids": [],
                "votes": {},
                "jurors": {
                    "@juror": {
                        "status": "accepted",
                        "accepted_at_height": 1,
                        "safe_withdraw_until_height": 10,
                        "vote_deadline_height": 20,
                        "reputation_policy": {
                            "late_withdraw_penalty_milli": -500,
                            "timeout_penalty_milli": -1500,
                        },
                    }
                },
            }
        },
    }


def test_late_withdraw_still_applies_legacy_penalty_to_currently_conflicted_juror(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state = _accepted_conflicted_state()
    case = state["disputes_by_id"]["case"]
    assert "@juror" in dispute._dispute_conflict_account_ids(state, case)
    events: list[dict] = []

    def record(_state: dict, **kwargs: object) -> dict:
        events.append(dict(kwargs))
        return {"event_id": "test-only-withdrawal"}

    monkeypatch.setattr(dispute, "_record_dispute_juror_reputation_event", record)
    result = dispute._apply_dispute_juror_withdraw(
        state,
        TxEnvelope(
            tx_type="DISPUTE_JUROR_WITHDRAW",
            signer="@juror",
            nonce=5,
            payload={"dispute_id": "case", "reason": "new_material_conflict"},
        ),
    )
    assert result["applied"] == "DISPUTE_JUROR_WITHDRAW"
    assert result["safe"] is False
    assert result["delta_milli"] == -500
    assert [event["event_type"] for event in events] == ["DISPUTE_JUROR_WITHDREW_LATE"]
    assert events[0]["reason"] == "late_withdraw_light_penalty"
    assert case["jurors"]["@juror"]["status"] == "withdrawn"
    assert case["jurors"]["@juror"]["withdrawal"]["delta_milli"] == -500
    assert case["jurors"]["@juror"]["withdrawal"]["reason"] == "new_material_conflict"


def test_direct_system_timeout_still_penalizes_currently_conflicted_juror(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state = _accepted_conflicted_state()
    case = state["disputes_by_id"]["case"]
    assert "@juror" in dispute._dispute_conflict_account_ids(state, case)
    events: list[dict] = []

    def record(_state: dict, **kwargs: object) -> dict:
        events.append(dict(kwargs))
        return {"event_id": "test-only-timeout"}

    monkeypatch.setattr(dispute, "_record_dispute_juror_reputation_event", record)
    result = dispute._apply_dispute_juror_timeout(
        state,
        TxEnvelope(
            tx_type="DISPUTE_JUROR_TIMEOUT",
            signer="SYSTEM",
            system=True,
            nonce=6,
            payload={"dispute_id": "case", "juror": "@juror"},
        ),
    )
    assert result["applied"] == "DISPUTE_JUROR_TIMEOUT"
    assert result["delta_milli"] == -1500
    assert [event["event_type"] for event in events] == ["DISPUTE_JUROR_TIMED_OUT"]
    assert events[0]["reason"] == "dispute_timeout_penalty"
    assert case["jurors"]["@juror"]["status"] == "timed_out"


def test_direct_final_accountability_flags_conflicted_nonvoter_without_vote() -> None:
    state = _accepted_conflicted_state()
    case = state["disputes_by_id"]["case"]
    before = deepcopy(case)
    assert "@juror" in dispute._dispute_conflict_account_ids(state, case)
    result = dispute._record_dispute_juror_accountability(state, case, dispute_id="case")
    assert result == {"applied": True, "jurors": ["@juror"]}
    assert state["accounts"]["@juror"]["dispute_juror_eligible"] is False
    assert (
        state["accounts"]["@juror"]["dispute_juror_suspended_reason"]
        == "assigned_dispute_vote_missed"
    )
    assert state["dispute_juror_accountability"]["by_juror"]["@juror"]["missed_vote_count"] == 1
    assert case == before, "direct accountability updated the account rather than the case"


@pytest.mark.parametrize("status", ("declined", "withdrawn", "timed_out"))
def test_existing_terminal_statuses_avoid_final_accountability_flag(status: str) -> None:
    state = _accepted_conflicted_state()
    case = state["disputes_by_id"]["case"]
    case["jurors"]["@juror"]["status"] = status
    result = dispute._record_dispute_juror_accountability(state, case, dispute_id="case")
    assert result == {"applied": False, "jurors": []}
    assert state["accounts"]["@juror"] == {}


def test_prior_cast_ballot_prevents_direct_final_accountability_flag() -> None:
    state = _accepted_conflicted_state()
    case = state["disputes_by_id"]["case"]
    case["voted_juror_ids"] = ["juror"]
    result = dispute._record_dispute_juror_accountability(state, case, dispute_id="case")
    assert result == {"applied": False, "jurors": []}
    assert state["accounts"]["@juror"] == {}
