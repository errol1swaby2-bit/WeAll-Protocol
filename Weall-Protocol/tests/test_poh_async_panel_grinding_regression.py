from __future__ import annotations

from copy import deepcopy

from weall.runtime.poh.async_scheduler import schedule_poh_async_system_txs
from weall.runtime.poh.juror_select import (
    async_request_selection_seed,
    pick_async_jurors,
)

REVIEWERS = [f"@reviewer-{index:02d}" for index in range(10)]
TARGET = "@applicant"
OPENED_HEIGHT = 7


def _state(*, case_id: str, beacon_output: str) -> dict:
    accounts = {
        TARGET: {
            "poh_tier": 0,
            "nonce": 0,
            "banned": False,
            "locked": False,
            "reputation_milli": 0,
        }
    }
    accounts.update(
        {
            reviewer: {
                "poh_tier": 2,
                "nonce": 0,
                "banned": False,
                "locked": False,
                "reputation_milli": 1000,
            }
            for reviewer in REVIEWERS
        }
    )
    return {
        "chain_id": "weall-prod",
        "height": 20,
        "tip": "tip-20",
        "rand": {
            "vrf": {
                "height": 20,
                "scheme": "mldsa_beacon_v2",
                "pubkey": "test",
                "output": beacon_output,
            }
        },
        "params": {
            "poh": {
                "async_n_jurors": 3,
                "async_min_reviews": 3,
                "async_approval_threshold": 2,
                "async_rejection_threshold": 2,
                "async_min_rep_milli": 0,
            }
        },
        "accounts": accounts,
        "roles": {
            "validators": {"active_set": REVIEWERS[:4]},
            "jurors": {
                "active_set": list(REVIEWERS),
                "by_id": {reviewer: {"active": True} for reviewer in REVIEWERS},
            },
        },
        "poh": {
            "async_cases": {
                case_id: {
                    "case_id": case_id,
                    "account_id": TARGET,
                    "opened_by": TARGET,
                    "opened_height": OPENED_HEIGHT,
                    "expires_height": 1000,
                    "status": "evidence_bound",
                    "evidence_binds": {
                        f"bind:{case_id}": {
                            "bind_id": f"bind:{case_id}",
                            "followup_round": 0,
                        }
                    },
                    "followup_round": 0,
                    "assigned_jurors": [],
                    "accepted_jurors": [],
                    "declined_jurors": [],
                    "reviews": {},
                    "configured_assigned_juror_count": 3,
                    "configured_minimum_reviews": 3,
                    "configured_approval_threshold": 2,
                    "configured_rejection_threshold": 2,
                    "assigned_juror_count": 3,
                    "minimum_reviews": 3,
                    "approval_threshold": 2,
                    "rejection_threshold": 2,
                }
            }
        },
    }


def _queued_assignment(state: dict) -> dict:
    queued = [
        item
        for item in list(state.get("system_queue") or [])
        if item.get("tx_type") == "POH_ASYNC_JUROR_ASSIGN"
    ]
    assert queued
    return queued[-1]


def test_async_case_id_grind_search_cannot_change_panel() -> None:
    state = _state(case_id="fixture-case", beacon_output="11" * 32)
    selection_seed = async_request_selection_seed(
        state=state,
        target_account=TARGET,
        opened_height=OPENED_HEIGHT,
    )

    panels = {
        tuple(
            pick_async_jurors(
                state=state,
                case_id=f"attacker-controlled-{candidate}",
                target_account=TARGET,
                n_jurors=3,
                selection_seed=selection_seed,
            )
        )
        for candidate in range(5000)
    }

    assert len(panels) == 1


def test_async_scheduler_case_label_and_beacon_do_not_change_panel() -> None:
    state_a = _state(case_id="candidate-A", beacon_output="22" * 32)
    state_b = _state(case_id="candidate-B", beacon_output="ee" * 32)

    assert schedule_poh_async_system_txs(state_a, next_height=21) == 1
    assert schedule_poh_async_system_txs(state_b, next_height=21) == 1

    panel_a = _queued_assignment(state_a)["payload"]["jurors"]
    panel_b = _queued_assignment(state_b)["payload"]["jurors"]
    assert panel_a == panel_b


def test_async_decline_replacement_uses_request_seed() -> None:
    state = _state(case_id="stable-request", beacon_output="33" * 32)
    selection_seed = async_request_selection_seed(
        state=state,
        target_account=TARGET,
        opened_height=OPENED_HEIGHT,
    )
    initial = pick_async_jurors(
        state=state,
        case_id="stable-request",
        target_account=TARGET,
        n_jurors=3,
        selection_seed=selection_seed,
    )
    expected_replacement = pick_async_jurors(
        state=state,
        case_id="arbitrary-replacement-label",
        target_account=TARGET,
        n_jurors=1,
        excluded_accounts=set(initial),
        selection_seed=selection_seed,
    )[0]

    replacement_state = deepcopy(state)
    case = replacement_state["poh"]["async_cases"]["stable-request"]
    case["status"] = "assigned"
    case["assigned_jurors"] = list(initial)
    case["declined_jurors"] = [initial[0]]
    replacement_state["rand"]["vrf"]["output"] = "ff" * 32

    assert schedule_poh_async_system_txs(replacement_state, next_height=21) == 1
    replacement_panel = _queued_assignment(replacement_state)["payload"]["jurors"]

    assert replacement_panel[:2] == initial[1:]
    assert replacement_panel[2] == expected_replacement
