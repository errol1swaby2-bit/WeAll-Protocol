"""Adversarial P0 test: a scoped electorate cannot authorize global effects.

These tests exercise the canonical governance domain and the immutable
approved-actions execution stage. Production launch gating is not a substitute
for an authorization boundary: use an active, strict controlled-testnet profile
to test the mature-network behavior.
"""
from __future__ import annotations

from copy import deepcopy

import pytest

from weall.runtime.apply.governance import _apply_gov_execute
from weall.runtime.domain_dispatch import apply_tx
from weall.runtime.errors import ApplyError
from weall.runtime.tx_admission_types import TxEnvelope


GLOBAL_ACTIONS = [
    {"tx_type": "GOV_QUORUM_SET", "payload": {"quorum_bps": 5_000}},
    {"tx_type": "GOV_RULES_SET", "payload": {"params": {"poh": {"tier2_n_jurors": 7}}}},
    {
        "tx_type": "VALIDATOR_SET_UPDATE",
        "payload": {"active_set": ["@validator"], "activate_at_epoch": 2},
    },
    {
        "tx_type": "PROTOCOL_UPGRADE_DECLARE",
        "payload": {"upgrade_id": "upgrade-x", "target_version": "2026.04"},
    },
]
GROUP_ACTION = {
    "tx_type": "GROUP_TREASURY_SPEND_EXECUTE",
    "payload": {"spend_id": "local-spend"},
}


def _env(tx_type: str, signer: str, nonce: int, payload: dict, *, system: bool = False) -> TxEnvelope:
    return TxEnvelope(
        tx_type=tx_type,
        signer=signer,
        nonce=nonce,
        payload=payload,
        system=system,
        sig="",
        chain_id="weall-controlled-testnet",
    )


def _state() -> dict:
    def account() -> dict:
        return {
            "nonce": 0,
            "poh_tier": 2,
            "reputation_milli": 5_000,
            "balance": 0,
            "banned": False,
            "locked": False,
        }

    return {
        "chain_id": "weall-controlled-testnet",
        "height": 20,
        "accounts": {
            "@captured": account(),
            "@independent-1": account(),
            "@independent-2": account(),
            "@validator": account(),
        },
        "roles": {
            "groups_by_id": {
                "group-small": {
                    "group_id": "group-small",
                    "members": {"@captured": {"account": "@captured", "role": "member"}},
                    "signers": ["@captured"],
                    "moderators": ["@captured"],
                },
            },
            "validators": {
                "active_set": ["@validator"],
                "by_id": {"@validator": {"status": "active", "active": True}},
            },
        },
        "params": {
            "mode": "controlled-testnet",
            "economics_enabled": True,
            "economic_unlock_time": 0,
            "gov_action_allowlist": [
                "GOV_QUORUM_SET",
                "GOV_RULES_SET",
                "VALIDATOR_SET_UPDATE",
                "PROTOCOL_UPGRADE_DECLARE",
                "GROUP_TREASURY_SPEND_EXECUTE",
            ],
        },
        "ballot_profile": {"profile_id": "controlled-testnet-aggregate-v1", "active": True},
        "gov_config": {},
        "system_queue": [],
    }


def _group_proposal(proposal_id: str, actions: list[dict]) -> dict:
    return {
        "proposal_id": proposal_id,
        "title": "Captured group's proposed action",
        "rules": {
            "group_id": "group-small",
            "electorate_scope": "group_members",
            "start_stage": "voting",
        },
        "actions": deepcopy(actions),
    }


@pytest.mark.parametrize("action", GLOBAL_ACTIONS, ids=lambda action: action["tx_type"])
def test_group_electorate_cannot_propose_global_action(action: dict) -> None:
    state = _state()
    with pytest.raises(ApplyError) as exc:
        apply_tx(
            state,
            _env("GOV_PROPOSAL_CREATE", "@captured", 1, _group_proposal("attack", [action])),
        )
    assert exc.value.reason == "governance_action_scope_mismatch"
    assert "attack" not in state.get("gov_proposals_by_id", {})
    assert not state["system_queue"]


def test_group_cannot_smuggle_global_action_in_mixed_action_batch() -> None:
    state = _state()
    with pytest.raises(ApplyError) as exc:
        apply_tx(
            state,
            _env(
                "GOV_PROPOSAL_CREATE",
                "@captured",
                1,
                _group_proposal("mixed", [GROUP_ACTION, GLOBAL_ACTIONS[0]]),
            ),
        )
    assert exc.value.reason == "governance_action_scope_mismatch"
    assert "mixed" not in state.get("gov_proposals_by_id", {})


def test_group_cannot_edit_global_action_into_earlier_draft() -> None:
    state = _state()
    proposal = _group_proposal("draft", [])
    proposal["rules"]["start_stage"] = "draft"
    apply_tx(state, _env("GOV_PROPOSAL_CREATE", "@captured", 1, proposal))
    before = deepcopy(state["gov_proposals_by_id"]["draft"])
    with pytest.raises(ApplyError) as exc:
        apply_tx(
            state,
            _env(
                "GOV_PROPOSAL_EDIT",
                "@captured",
                2,
                {"proposal_id": "draft", "actions": [GLOBAL_ACTIONS[0]]},
            ),
        )
    assert exc.value.reason == "governance_action_scope_mismatch"
    assert state["gov_proposals_by_id"]["draft"] == before


@pytest.mark.parametrize("action", GLOBAL_ACTIONS, ids=lambda action: action["tx_type"])
def test_preexisting_passed_group_proposal_cannot_execute_global_action(action: dict) -> None:
    state = _state()
    state["gov_proposals_by_id"] = {
        "preexisting": {
            "proposal_id": "preexisting",
            "group_id": "group-small",
            "electorate_scope": "group_members",
            "stage": "tallied",
            "actions": [action],
            "tallies": [{"height": 19, "payload": {"passed": True}}],
        }
    }
    with pytest.raises(ApplyError) as exc:
        _apply_gov_execute(
            state,
            _env("GOV_EXECUTE", "SYSTEM", 0, {"proposal_id": "preexisting"}, system=True),
        )
    assert exc.value.reason == "governance_action_scope_mismatch"
    assert not state["system_queue"]
    assert state["gov_config"] == {}


def test_group_treasury_governance_remains_allowed_at_its_own_scope() -> None:
    state = _state()
    apply_tx(
        state,
        _env("GOV_PROPOSAL_CREATE", "@captured", 1, _group_proposal("spend", [GROUP_ACTION])),
    )
    proposal = state["gov_proposals_by_id"]["spend"]
    assert proposal["electorate_scope"] == "group_members"
    assert proposal["eligible_voter_ids"] == ["@captured"]
    assert proposal["actions"] == [GROUP_ACTION]


def test_protocol_human_electorate_may_propose_global_action() -> None:
    state = _state()
    apply_tx(
        state,
        _env(
            "GOV_PROPOSAL_CREATE",
            "@captured",
            1,
            {
                "proposal_id": "protocol-vote",
                "rules": {"start_stage": "voting", "electorate_scope": "protocol_tier2"},
                "actions": [GLOBAL_ACTIONS[0]],
            },
        ),
    )
    proposal = state["gov_proposals_by_id"]["protocol-vote"]
    assert proposal["electorate_scope"] == "protocol_tier2"
    assert len(proposal["eligible_voter_ids"]) == 4
    assert proposal["actions"] == [GLOBAL_ACTIONS[0]]
