"""Characterize the current fail-closed validator-set composition boundary.

These tests do not define a new policy for combining separately approved
validator operations. They show why that policy needs a consensus-level
decision before the four-validator authorization rehearsal can advance.
"""

from __future__ import annotations

import copy

import pytest

from weall.runtime.apply.consensus import ConsensusApplyError, apply_consensus
from weall.runtime.tx_admission import TxEnvelope

CANDIDATES = ("@candidate_a", "@candidate_b")


def _state() -> dict:
    registry = {
        account: {
            "account": account,
            "pubkey": ("a1" if account == CANDIDATES[0] else "b2") * 32,
            "status": "candidate",
            "active": False,
        }
        for account in CANDIDATES
    }
    return {
        "height": 0,
        "roles": {"validators": {"active_set": []}},
        "consensus": {
            "validator_set": {"active_set": [], "epoch": 0, "set_hash": ""},
            "epochs": {"current": 0},
            "validators": {
                "registry": {
                    account: {"pubkey": rec["pubkey"], "status": "candidate"}
                    for account, rec in registry.items()
                }
            },
        },
        "validators": {"registry": registry},
    }


def _approve(state: dict, account: str, epoch: int = 1) -> dict:
    result = apply_consensus(
        state,
        TxEnvelope(
            tx_type="VALIDATOR_CANDIDATE_APPROVE",
            signer="SYSTEM",
            nonce=0,
            payload={"account": account, "activate_at_epoch": epoch},
            sig="",
            parent=f"approved-proposal-for-{account}",
            system=True,
        ),
    )
    assert isinstance(result, dict)
    return result


@pytest.mark.parametrize("first,second", [CANDIDATES, CANDIDATES[::-1]])
def test_two_distinct_approvals_for_one_epoch_fail_closed(first: str, second: str) -> None:
    state = _state()
    _approve(state, first)
    before_pending = copy.deepcopy(state["consensus"]["validator_set"]["pending"])

    with pytest.raises(ConsensusApplyError) as caught:
        _approve(state, second)

    assert caught.value.code == "invalid_payload"
    assert caught.value.reason == "validator_set_pending_update_exists"
    assert state["consensus"]["validator_set"]["pending"] == before_pending
    assert state["consensus"]["validator_set"]["active_set"] == []
    assert state["validators"]["registry"][second]["status"] == "candidate"


def test_repeating_identical_approval_is_idempotent_for_pending_set() -> None:
    state = _state()
    first = _approve(state, CANDIDATES[0])
    pending_before = copy.deepcopy(state["consensus"]["validator_set"]["pending"])

    second = _approve(state, CANDIDATES[0])

    assert first["validator_set_hash"] == second["validator_set_hash"]
    assert state["consensus"]["validator_set"]["pending"] == pending_before


def test_different_target_epoch_is_not_silently_queued() -> None:
    state = _state()
    _approve(state, CANDIDATES[0], epoch=1)
    before_pending = copy.deepcopy(state["consensus"]["validator_set"]["pending"])

    with pytest.raises(ConsensusApplyError) as caught:
        _approve(state, CANDIDATES[1], epoch=2)

    assert caught.value.reason == "validator_set_pending_update_exists"
    assert state["consensus"]["validator_set"]["pending"] == before_pending


def _full_set_update(state: dict, members: list[str], epoch: int = 1) -> dict:
    result = apply_consensus(
        state,
        TxEnvelope(
            tx_type="VALIDATOR_SET_UPDATE",
            signer="SYSTEM",
            nonce=0,
            payload={"active_set": members, "activate_at_epoch": epoch},
            sig="",
            parent="aggregate-set-governance-fixture",
            system=True,
        ),
    )
    assert isinstance(result, dict)
    return result


def test_existing_full_set_action_schedules_both_candidates_without_new_aggregator() -> None:
    state = _state()
    result = _full_set_update(state, list(reversed(CANDIDATES)))

    assert result["pending"] is True
    pending = state["consensus"]["validator_set"]["pending"]
    assert pending["active_set"] == sorted(CANDIDATES)
    assert pending["activate_at_epoch"] == 1
    assert state["consensus"]["validator_set"]["active_set"] == []


def test_individual_approval_does_not_silently_expand_prior_full_set() -> None:
    state = _state()
    _full_set_update(state, [CANDIDATES[0]])
    pending_before = copy.deepcopy(state["consensus"]["validator_set"]["pending"])

    with pytest.raises(ConsensusApplyError) as caught:
        _approve(state, CANDIDATES[1])

    assert caught.value.reason == "validator_set_pending_update_exists"
    assert state["consensus"]["validator_set"]["pending"] == pending_before
    assert state["validators"]["registry"][CANDIDATES[1]]["status"] == "candidate"


def test_full_set_update_does_not_override_prior_individual_approval() -> None:
    state = _state()
    _approve(state, CANDIDATES[0])
    pending_before = copy.deepcopy(state["consensus"]["validator_set"]["pending"])

    with pytest.raises(ConsensusApplyError) as caught:
        _full_set_update(state, list(CANDIDATES))

    assert caught.value.reason == "validator_set_pending_update_exists"
    assert state["consensus"]["validator_set"]["pending"] == pending_before
    assert state["consensus"]["validator_set"]["active_set"] == []
