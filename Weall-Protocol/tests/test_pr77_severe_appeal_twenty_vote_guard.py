"""Structural 20/25 severe-appeal guard. NOT automatic-appeal authorization."""

from __future__ import annotations

import copy

import pytest

from weall.runtime.apply import dispute
from weall.runtime.ballot_policy import CONTROLLED_TESTNET_BALLOT_PROFILE
from weall.runtime.dispute_engine import tick_dispute_lifecycle
from weall.runtime.tx_admission_types import TxEnvelope


def _env(kind: str, who: str, nonce: int, payload: dict) -> TxEnvelope:
    return TxEnvelope(tx_type=kind, signer=who, nonce=nonce, payload=payload, sig="")


def _state() -> dict:
    reviewers = [f"@reviewer-{i:03d}" for i in range(90)]
    return {
        "height": 100,
        "chain_id": "synthetic-severe-appeal",
        "params": {"mode": "controlled-testnet", "m3_civic_governance_strict": True},
        "meta": {"constitutional_clock": {"enabled": True}},
        "ballot_profile": {"profile_id": CONTROLLED_TESTNET_BALLOT_PROFILE, "active": True},
        "accounts": {
            **{j: {"poh_tier": 2, "banned": False, "locked": False} for j in reviewers},
            "@target": {"poh_tier": 2, "banned": False, "locked": False},
        },
        "roles": {"jurors": {"active_set": reviewers, "by_id": {}}},
        "disputes_by_id": {
            "s4": {
                "id": "s4",
                "target_type": "account",
                "target_id": "@target",
                "target_owner": "@target",
                "opened_by": "@reporter",
                "appeal_allowed_accounts": ["@target"],
                "sanction_class": "S4",
                "severity": "severe",
                "stage": "appeal_window",
                "resolved": True,
                "resolution": {"outcome": "report_upheld"},
                "appeal_deadline_height": 150,
                "appeals": [],
                "assigned_jurors": reviewers[:25],
                "substitute_juror_ids": reviewers[25:30],
                "panel_status": "assigned",
                "panel_commitment": "synthetic-commitment",
                "panel_round": 1,
                "opened_at_height": 20,
                "jurors": {},
                "votes": {},
            }
        },
        "system_queue": [],
    }


def _ready() -> tuple[dict, list[str]]:
    state = _state()
    dispute.apply_dispute(state, _env("DISPUTE_APPEAL", "@target", 1, {"dispute_id": "s4"}))
    d = state["disputes_by_id"]["s4"]
    assert d["appeal_panel_status"] == "assigned"
    assert d["required_votes"] == 20
    assert dispute._severe_fresh_appeal_panel_observed(d)
    return state, list(d["appeal_panel_juror_ids"])


def test_seventeen_ordinary_votes_cannot_resolve_severe_appeal() -> None:
    state, panel = _ready()
    for index, juror in enumerate(panel[:20], 1):
        dispute.apply_dispute(state, _env("DISPUTE_JUROR_ACCEPT", juror, 10 + index, {"dispute_id": "s4"}))
    for index, juror in enumerate(panel[:20], 1):
        result = dispute.apply_dispute(
            state,
            _env("DISPUTE_VOTE_SUBMIT", juror, 40 + index, {"dispute_id": "s4", "appeal_decision": "uphold"}),
        )
        assert result["appeal_panel_result"]["required_votes"] == 20
        assert result["appeal_panel_result"]["reached"] is (index == 20)
        if index == 17:
            assert state["disputes_by_id"]["s4"]["stage"] == "appeal_review"
    d = state["disputes_by_id"]["s4"]
    assert d["appeal_vote_counts"] == {"uphold": 20}
    assert d["stage"] == "appeal_resolved"
    assert tick_dispute_lifecycle(state, next_height=101) == 0
    assert not any(q.get("tx_type") in {"ACCOUNT_BAN", "DISPUTE_FINAL_RECEIPT"} for q in state["system_queue"])


@pytest.mark.parametrize("fault", ["round", "panel", "substitutes", "original", "commitment", "status", "assigned"])
def test_structurally_invalid_second_panel_refuses_vote_without_mutation(fault: str) -> None:
    state, panel = _ready()
    d = state["disputes_by_id"]["s4"]
    if fault == "round":
        d["appeal_panel_round"] = 1
    elif fault == "panel":
        d["appeal_panel_juror_ids"][-1] = d["original_panel_juror_ids"][0]
    elif fault == "substitutes":
        d["appeal_substitute_juror_ids"].pop()
    elif fault == "original":
        d["original_panel_juror_ids"].pop()
    elif fault == "commitment":
        d["appeal_panel_commitment"] = ""
    elif fault == "status":
        d["appeal_panel_status"] = "insufficient_reviewer_pool"
    elif fault == "assigned":
        d["assigned_jurors"] = list(reversed(d["assigned_jurors"]))
    before = copy.deepcopy(state)
    with pytest.raises(dispute.DisputeApplyError) as exc:
        dispute.apply_dispute(state, _env("DISPUTE_VOTE_SUBMIT", panel[0], 12, {"dispute_id": "s4", "appeal_decision": "uphold"}))
    assert exc.value.code == "forbidden"
    assert exc.value.reason == "severe_appeal_fresh_panel_unverified"
    assert state == before


def test_legacy_clock_preserves_manual_appeal_vote_path() -> None:
    state, panel = _ready()
    state["meta"]["constitutional_clock"]["enabled"] = False
    d = state["disputes_by_id"]["s4"]
    d["appeal_panel_round"] = 1
    dispute.apply_dispute(state, _env("DISPUTE_JUROR_ACCEPT", panel[0], 2, {"dispute_id": "s4"}))
    result = dispute.apply_dispute(
        state, _env("DISPUTE_VOTE_SUBMIT", panel[0], 3, {"dispute_id": "s4", "appeal_decision": "uphold"})
    )
    assert result["appeal_panel_result"]["votes"] == 1
