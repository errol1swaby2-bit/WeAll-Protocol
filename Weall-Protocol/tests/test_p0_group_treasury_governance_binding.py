from __future__ import annotations

import pytest

from weall.runtime.apply.governance import _apply_gov_execute
from weall.runtime.apply.groups import GroupsApplyError, apply_groups
from weall.runtime.errors import ApplyError
from weall.runtime.group_treasury_scheduler import (
    group_spend_plan_hash,
    maybe_enqueue_group_spend_execute,
)
from weall.runtime.tx_admission_types import TxEnvelope


def _economic_state() -> dict:
    return {
        "chain_id": "weall-prod",
        "height": 20,
        "time": 100,
        "params": {
            "economic_unlock_time": 0,
            "economics_enabled": True,
        },
        "system_queue": [],
    }


def _signed_spend() -> dict:
    return {
        "spend_id": "spend-1",
        "group_id": "group-1",
        "treasury_id": "TREASURY_GROUP::group-1",
        "to": "@recipient",
        "amount": 10,
        "status": "proposed",
        "signatures": {"@signer": {"at_nonce": 1}},
        "allowed_signers": ["@signer"],
        "threshold": 1,
        "created_at_height": 10,
        "earliest_execute_height": 15,
    }


def test_strict_multisig_threshold_does_not_schedule_without_governance_approval() -> None:
    state = _economic_state()
    spend = _signed_spend()

    assert maybe_enqueue_group_spend_execute(state, spend=spend) is None
    assert state["system_queue"] == []


def test_strict_execute_rejects_missing_governance_approval() -> None:
    state = _economic_state()
    state["group_treasury_spends"] = {"spend-1": _signed_spend()}

    env = TxEnvelope(
        tx_type="GROUP_TREASURY_SPEND_EXECUTE",
        signer="SYSTEM",
        nonce=0,
        payload={"spend_id": "spend-1"},
        system=True,
        chain_id="weall-prod",
    )

    with pytest.raises(GroupsApplyError) as exc_info:
        apply_groups(state, env)

    assert exc_info.value.reason == "group_spend_governance_approval_required"


def test_governance_execute_binds_group_spend_plan_and_queues_signed_execution() -> None:
    state = _economic_state()
    spend = _signed_spend()
    state["group_treasury_spends"] = {"spend-1": spend}
    action = {
        "tx_type": "GROUP_TREASURY_SPEND_EXECUTE",
        "payload": {"spend_id": "spend-1"},
    }
    state["gov_proposals_by_id"] = {
        "proposal-1": {
            "proposal_id": "proposal-1",
            "stage": "tallied",
            "group_id": "group-1",
            "electorate_scope": "group_members",
            "electorate_commitment": "electorate-commitment-1",
            "actions": [action],
            "tallied_at_height": 19,
            "tallies": [{"height": 19, "payload": {"passed": True}}],
        }
    }
    env = TxEnvelope(
        tx_type="GOV_EXECUTE",
        signer="SYSTEM",
        nonce=0,
        payload={"proposal_id": "proposal-1", "actions": [action]},
        system=True,
        chain_id="weall-prod",
    )

    result = _apply_gov_execute(state, env)

    assert result == {"applied": True, "proposal_id": "proposal-1"}
    approval = spend["governance_approval"]
    assert approval["proposal_id"] == "proposal-1"
    assert approval["group_id"] == "group-1"
    assert approval["amount"] == 10
    assert approval["to"] == "@recipient"
    assert approval["spend_plan_hash"] == group_spend_plan_hash(spend)
    queued = [
        row for row in state["system_queue"] if row.get("tx_type") == "GROUP_TREASURY_SPEND_EXECUTE"
    ]
    assert len(queued) == 1
    payload = queued[0]["payload"]
    assert payload["_governance_proposal_id"] == "proposal-1"
    assert payload["_approved_spend_plan_hash"] == approval["spend_plan_hash"]


def test_governance_approved_signed_group_spend_moves_value_once() -> None:
    state = _economic_state()
    state["accounts"] = {
        "@recipient": {
            "balance": 0,
            "nonce": 0,
            "poh_tier": 2,
            "banned": False,
            "locked": False,
        }
    }
    state["treasury_wallets"] = {
        "TREASURY_GROUP::group-1": {
            "wallet_id": "TREASURY_GROUP::group-1",
            "balance": 25,
        }
    }
    spend = _signed_spend()
    state["group_treasury_spends"] = {"spend-1": spend}
    action = {
        "tx_type": "GROUP_TREASURY_SPEND_EXECUTE",
        "payload": {"spend_id": "spend-1"},
    }
    state["gov_proposals_by_id"] = {
        "proposal-1": {
            "proposal_id": "proposal-1",
            "stage": "tallied",
            "group_id": "group-1",
            "electorate_scope": "group_members",
            "electorate_commitment": "electorate-commitment-1",
            "actions": [action],
            "tallied_at_height": 19,
            "tallies": [{"height": 19, "payload": {"passed": True}}],
        }
    }

    _apply_gov_execute(
        state,
        TxEnvelope(
            tx_type="GOV_EXECUTE",
            signer="SYSTEM",
            nonce=0,
            payload={"proposal_id": "proposal-1", "actions": [action]},
            system=True,
            chain_id="weall-prod",
        ),
    )
    queued = [
        row for row in state["system_queue"] if row.get("tx_type") == "GROUP_TREASURY_SPEND_EXECUTE"
    ]
    assert len(queued) == 1

    result = apply_groups(
        state,
        TxEnvelope(
            tx_type="GROUP_TREASURY_SPEND_EXECUTE",
            signer="SYSTEM",
            nonce=1,
            payload=dict(queued[0]["payload"]),
            system=True,
            chain_id="weall-prod",
        ),
    )

    assert result == {
        "applied": "GROUP_TREASURY_SPEND_EXECUTE",
        "spend_id": "spend-1",
        "to": "@recipient",
        "amount": 10,
    }
    assert state["treasury_wallets"]["TREASURY_GROUP::group-1"]["balance"] == 15
    assert state["accounts"]["@recipient"]["balance"] == 10
    assert spend["status"] == "executed"
    assert spend["transferred_to"] == "@recipient"
    assert spend["transferred_amount"] == 10


def test_strict_execute_rejects_spend_plan_mutation_after_governance_approval() -> None:
    state = _economic_state()
    spend = _signed_spend()
    approved_hash = group_spend_plan_hash(spend)
    spend["governance_approval"] = {
        "proposal_id": "proposal-1",
        "spend_plan_hash": approved_hash,
    }
    spend["amount"] = 11
    state["group_treasury_spends"] = {"spend-1": spend}
    env = TxEnvelope(
        tx_type="GROUP_TREASURY_SPEND_EXECUTE",
        signer="SYSTEM",
        nonce=0,
        payload={
            "spend_id": "spend-1",
            "_governance_proposal_id": "proposal-1",
            "_approved_spend_plan_hash": approved_hash,
        },
        system=True,
        chain_id="weall-prod",
    )

    with pytest.raises(GroupsApplyError) as exc_info:
        apply_groups(state, env)

    assert exc_info.value.reason == "group_spend_governance_plan_mismatch"


def test_strict_governance_execute_rejects_actions_not_approved_by_voters() -> None:
    state = _economic_state()
    approved_action = {
        "tx_type": "GOV_QUORUM_SET",
        "payload": {"quorum_percent": 60},
    }
    state["gov_proposals_by_id"] = {
        "proposal-1": {
            "proposal_id": "proposal-1",
            "stage": "tallied",
            "actions": [approved_action],
            "tallies": [{"height": 19, "payload": {"passed": True}}],
        }
    }
    env = TxEnvelope(
        tx_type="GOV_EXECUTE",
        signer="SYSTEM",
        nonce=0,
        payload={
            "proposal_id": "proposal-1",
            "actions": [
                {
                    "tx_type": "GOV_QUORUM_SET",
                    "payload": {"quorum_percent": 90},
                }
            ],
        },
        system=True,
        chain_id="weall-prod",
    )

    with pytest.raises(ApplyError) as exc_info:
        _apply_gov_execute(state, env)

    assert exc_info.value.reason == "governance_execution_actions_mismatch"
