"""PR77 strict fresh appeal-panel formation and failed-appeal atomicity.

These are deterministic domain transitions on synthetic ledger state. They do
not authenticate a public PoH pool, signatures, independent BFT or S4 sanction
authority. Signed executor replay is covered separately.
"""

from __future__ import annotations

from copy import deepcopy

import pytest

from weall.runtime.apply.dispute import DisputeApplyError, apply_dispute
from weall.runtime.tx_admission_types import TxEnvelope


def _state(*, jurors: int = 17) -> dict:
    roster = [f"@juror-{n:02d}" for n in range(jurors)]
    active = {
        "active": True,
        "responsibilities": {
            "reviewer": {"dispute_review": {"active": True, "opted_in": True}}
        },
    }
    return {
        "chain_id": "strict-local-appeal-fixture",
        "height": 25,
        "meta": {"constitutional_clock": {"enabled": True}},
        "params": {
            "mode": "controlled-testnet",
            "m3_civic_governance_strict": True,
        },
        "accounts": {
            "@subject": {"poh_tier": 2, "banned": False, "locked": False},
            "@outsider": {"poh_tier": 2, "banned": False, "locked": False},
            **{
                account: {"poh_tier": 2, "banned": False, "locked": False}
                for account in roster
            },
        },
        "roles": {
            "jurors": {
                "active_set": list(roster),
                "by_id": {account: deepcopy(active) for account in roster},
            }
        },
        "disputes_by_id": {
            "ordinary-account-review": {
                "id": "ordinary-account-review",
                "target_type": "account",
                "target_id": "@subject",
                "target_owner": "@subject",
                "stage": "appeal_window",
                "resolved": True,
                "appeal_allowed_accounts": ["@subject"],
                "appeal_deadline_height": 80,
                "assigned_jurors": roster[:7],
                "substitute_juror_ids": roster[7:9],
                "panel_round": 1,
                "appeals": [],
                "votes": {},
                "jurors": {},
            }
        },
        "system_queue": [],
    }


def _appeal(signer: str = "@subject", *, nonce: int = 1) -> TxEnvelope:
    return TxEnvelope(
        tx_type="DISPUTE_APPEAL",
        signer=signer,
        nonce=nonce,
        payload={"dispute_id": "ordinary-account-review", "reason": "Synthetic independent appeal"},
        sig="synthetic-not-verified",
        system=False,
    )


def _case(state: dict) -> dict:
    return state["disputes_by_id"]["ordinary-account-review"]


def test_insufficient_fresh_strict_panel_rejects_without_recording_appeal() -> None:
    # 7 original reviewers plus 2 substitutes leave 8 fresh candidates.
    # A strict ordinary case needs 7 new reviewers and 2 new substitutes.
    state = _state(jurors=17)
    before = deepcopy(state)
    with pytest.raises(DisputeApplyError) as exc:
        apply_dispute(state, _appeal())
    assert exc.value.code == "forbidden"
    assert exc.value.reason == "insufficient_fresh_appeal_panel"
    assert state == before
    assert _case(state)["appeals"] == []
    assert _case(state)["stage"] == "appeal_window"
    assert state["system_queue"] == []


def test_fresh_strict_appeal_panel_is_disjoint_deterministic_and_recorded_once() -> None:
    state = _state(jurors=18)
    independent = deepcopy(state)
    outcome = apply_dispute(state, _appeal())
    second = apply_dispute(independent, _appeal())
    assert outcome == second
    assert state == independent
    case = _case(state)
    assert outcome["applied"] == "DISPUTE_APPEAL"
    assert case["stage"] == "appeal_review"
    assert case["appeal_panel_round"] == 2
    assert case["appeal_panel_status"] == "assigned"
    assert len(case["appeal_panel_juror_ids"]) == 7
    assert len(case["appeal_substitute_juror_ids"]) == 2
    assert len(set(case["appeal_panel_juror_ids"] + case["appeal_substitute_juror_ids"])) == 9
    assert set(case["appeal_panel_juror_ids"] + case["appeal_substitute_juror_ids"]).isdisjoint(
        set(case["original_panel_juror_ids"] + case["original_substitute_juror_ids"])
    )
    assert "@subject" not in case["appeal_panel_juror_ids"]
    assert case["required_votes"] > 0
    assert case["appeals"] == [
        {
            "by": "@subject",
            "at_nonce": 1,
            "height": 25,
            "payload": {
                "dispute_id": "ordinary-account-review",
                "reason": "Synthetic independent appeal",
            },
        }
    ]
    assert state["system_queue"] == []


def test_duplicate_and_unauthorized_appeals_do_not_mutate_strict_state() -> None:
    state = _state(jurors=18)
    before = deepcopy(state)
    with pytest.raises(DisputeApplyError) as outsider:
        apply_dispute(state, _appeal("@outsider"))
    assert outsider.value.reason == "appeal_not_target_owner"
    assert state == before

    apply_dispute(state, _appeal())
    after_first = deepcopy(state)
    with pytest.raises(DisputeApplyError) as duplicate:
        apply_dispute(state, _appeal(nonce=2))
    assert duplicate.value.reason == "appeal_already_filed"
    assert state == after_first


def test_expired_strict_appeal_window_does_not_mutate_state() -> None:
    state = _state(jurors=18)
    state["height"] = 81
    before = deepcopy(state)
    with pytest.raises(DisputeApplyError) as exc:
        apply_dispute(state, _appeal())
    assert exc.value.reason == "appeal_window_closed"
    assert state == before
