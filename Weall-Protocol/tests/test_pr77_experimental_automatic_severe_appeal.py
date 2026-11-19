"""Default-off, deterministic automatic severe appeal assignment prototype.

The testbed does not authenticate the severe case class or original ballots.
No test here authorizes ACCOUNT_BAN or public-testnet activation.
"""

from __future__ import annotations

import copy

import pytest

from weall.runtime.apply import dispute
from weall.runtime.dispute_engine import tick_dispute_lifecycle
from weall.runtime.tx_admission import TxEnvelope


def _state(*, enabled: bool, reviewers: int = 90) -> dict:
    original = [f"@juror-{n:03d}" for n in range(25)]
    subs = [f"@juror-{n:03d}" for n in range(25, 30)]
    all_jurors = [f"@juror-{n:03d}" for n in range(reviewers)]
    voted = original[:20]
    nullifiers = {
        dispute._dispute_ballot_nullifier(
            dispute_id="severe-case", panel_round=1, juror=j, appeal=False
        ): {"final": True, "panel_round": 1}
        for j in voted
    }
    role = {
        "active": True,
        "responsibilities": {"reviewer": {"dispute_review": {"active": True, "opted_in": True}}},
    }
    return {
        "height": 11,
        "chain_id": "experimental-auto-appeal-fixture",
        "meta": {"constitutional_clock": {"enabled": True}},
        "params": {
            "mode": "controlled-testnet",
            "m3_civic_governance_strict": True,
            "experimental_severe_auto_appeal_v0": enabled,
        },
        "accounts": {
            **{j: {"poh_tier": 2, "banned": False, "locked": False} for j in all_jurors},
            "@target": {"poh_tier": 2, "banned": False, "locked": False},
        },
        "roles": {
            "jurors": {
                "active_set": all_jurors,
                "by_id": {j: copy.deepcopy(role) for j in all_jurors},
            }
        },
        "disputes_by_id": {
            "severe-case": {
                "id": "severe-case",
                "target_type": "account",
                "target_id": "@target",
                "sanction_class": "S4",
                "stage": "juror_review",
                "panel_status": "assigned",
                "panel_round": 1,
                "panel_commitment": "unverified-first-panel",
                "assigned_jurors": original,
                "substitute_juror_ids": subs,
                "eligible_juror_ids": original,
                "vote_counts": {"yes": 20},
                "voted_juror_ids": voted,
                "ballot_nullifiers": nullifiers,
                "votes": {},
                "resolved": False,
            }
        },
        "system_queue": [],
    }


def _resolve(state: dict) -> dict:
    return dispute.apply_dispute(
        state,
        TxEnvelope(
            tx_type="DISPUTE_RESOLVE",
            signer="SYSTEM",
            nonce=12,
            system=True,
            payload={
                "dispute_id": "severe-case",
                "resolution": {"outcome": "report_upheld", "summary": "synthetic"},
                "_system_queue_id": "unverified-parent-queue-ref",
            },
        ),
    )


def test_opt_in_assigns_deterministic_fresh_panel_without_enforcement() -> None:
    state = _state(enabled=True)
    original = copy.deepcopy(state)
    _resolve(state)
    d = state["disputes_by_id"]["severe-case"]
    assert d["stage"] == "appeal_review"
    assert d["appeal_panel_status"] == "assigned"
    assert d["appeal_panel_round"] == 2
    assert d["required_votes"] == 20
    assert len(d["appeal_panel_juror_ids"]) == 25
    assert len(d["appeal_substitute_juror_ids"]) == 5
    assert (
        len(
            {
                x.removeprefix("@")
                for x in (
                    d["original_panel_juror_ids"]
                    + d["original_substitute_juror_ids"]
                    + d["appeal_panel_juror_ids"]
                    + d["appeal_substitute_juror_ids"]
                )
            }
        )
        == 60
    )
    assert d["automatic_appeal_record"]["source"] == "experimental_system_resolution_v0"
    assert tick_dispute_lifecycle(state, next_height=12) == 0
    assert not state["system_queue"]
    replica = copy.deepcopy(original)
    _resolve(replica)
    assert replica == state


def test_disabled_default_preserves_historical_appeal_window() -> None:
    state = _state(enabled=False)
    _resolve(state)
    d = state["disputes_by_id"]["severe-case"]
    assert d["stage"] == "appeal_window"
    assert "automatic_appeal_record" not in d
    assert not state["system_queue"]


def test_enabled_but_insufficient_fresh_roster_remains_unfinalized() -> None:
    state = _state(enabled=True, reviewers=50)
    _resolve(state)
    d = state["disputes_by_id"]["severe-case"]
    assert d["stage"] == "appeal_window"
    assert d["experimental_auto_appeal_blocker"] == "insufficient_fresh_reviewers"
    assert not state["system_queue"]
    assert tick_dispute_lifecycle(state, next_height=1000) == 0


def test_duplicate_system_resolution_cannot_replace_appeal_panel() -> None:
    state = _state(enabled=True)
    _resolve(state)
    prior = copy.deepcopy(state)
    with pytest.raises(dispute.DisputeApplyError) as exc:
        _resolve(state)
    assert exc.value.reason == "automatic_severe_appeal_already_assigned"
    assert state == prior


def test_manual_appeal_cannot_replace_experimental_automatic_panel() -> None:
    state = _state(enabled=True)
    _resolve(state)
    prior = copy.deepcopy(state)
    with pytest.raises(dispute.DisputeApplyError) as exc:
        dispute.apply_dispute(
            state,
            TxEnvelope(
                tx_type="DISPUTE_APPEAL",
                signer="@target",
                nonce=13,
                payload={"dispute_id": "severe-case"},
            ),
        )
    assert exc.value.reason == "automatic_severe_appeal_already_assigned"
    assert state == prior


def test_boolean_true_required_no_truthy_strings() -> None:
    state = _state(enabled=False)
    state["params"]["experimental_severe_auto_appeal_v0"] = "true"
    _resolve(state)
    assert "automatic_appeal_record" not in state["disputes_by_id"]["severe-case"]


def test_legacy_clock_does_not_assign_automatic_panel() -> None:
    state = _state(enabled=True)
    state["meta"]["constitutional_clock"]["enabled"] = False
    _resolve(state)
    assert "automatic_appeal_record" not in state["disputes_by_id"]["severe-case"]
