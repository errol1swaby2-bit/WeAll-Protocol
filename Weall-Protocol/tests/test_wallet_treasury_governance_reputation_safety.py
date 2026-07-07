from __future__ import annotations

import pytest

from weall.ledger.constants import MINT_POOL_ACCOUNT_ID
from weall.runtime.apply.economics import EconomicsApplyError, apply_economics
from weall.runtime.apply.governance import apply_governance
from weall.runtime.apply.groups import GroupsApplyError, apply_groups
from weall.runtime.apply.rewards import RewardsApplyError, apply_rewards
from weall.runtime.apply.roles import RolesApplyError, apply_roles
from weall.runtime.apply.treasury import TreasuryApplyError, apply_treasury
from weall.runtime.errors import ApplyError
from weall.runtime.tx_admission_types import TxEnvelope


def _env(tx_type: str, signer: str, nonce: int, payload: dict, *, system: bool = False) -> TxEnvelope:
    return TxEnvelope(
        tx_type=tx_type,
        signer=signer,
        nonce=nonce,
        payload=payload,
        sig="sig",
        parent=f"parent:{nonce - 1}" if system else None,
        system=system,
    )


def _econ_state() -> dict:
    return {
        "height": 10,
        "time": 1,
        "params": {"economic_unlock_time": 0, "economics_enabled": True},
        "accounts": {
            "@alice": {
                "nonce": 0,
                "poh_tier": 1,
                "banned": False,
                "locked": False,
                "balance": 100,
                "reputation": "10",
                "keys": [],
            }
        },
    }


def test_balance_transfer_rejects_missing_recipient_without_creating_ghost_account() -> None:
    state = _econ_state()

    with pytest.raises(EconomicsApplyError) as excinfo:
        apply_economics(
            state,
            _env(
                "BALANCE_TRANSFER",
                "@alice",
                1,
                {"to": "@ghost", "amount": 25},
            ),
        )

    assert excinfo.value.reason == "to_account_missing"
    assert "@ghost" not in state["accounts"]
    assert state["accounts"]["@alice"]["balance"] == 100


def test_treasury_spend_execute_moves_balances_and_records_transfer() -> None:
    state = {
        "height": 10,
        "time": 1,
        "params": {"economic_unlock_time": 0, "economics_enabled": True},
        "accounts": {"@bob": {"balance": 0, "nonce": 0, "poh_tier": 2, "banned": False, "locked": False}},
        "treasury_wallets": {"TREASURY_PROTOCOL": {"wallet_id": "TREASURY_PROTOCOL", "balance": 1000}},
        "treasury": {
            "spends": {
                "spend-1": {
                    "spend_id": "spend-1",
                    "treasury_id": "TREASURY_PROTOCOL",
                    "status": "proposed",
                    "allowed_signers": ["@alice"],
                    "threshold": 1,
                    "signatures": {"@alice": {"at_nonce": 1}},
                    "earliest_execute_height": 1,
                    "to": "@bob",
                    "amount": 125,
                    "payload": {"to": "@bob", "amount": 125},
                }
            }
        },
    }

    result = apply_treasury(
        state,
        _env("TREASURY_SPEND_EXECUTE", "SYSTEM", 2, {"spend_id": "spend-1"}, system=True),
    )

    assert result == {
        "applied": "TREASURY_SPEND_EXECUTE",
        "spend_id": "spend-1",
        "to": "@bob",
        "amount": 125,
    }
    assert state["treasury_wallets"]["TREASURY_PROTOCOL"]["balance"] == 875
    assert state["accounts"]["@bob"]["balance"] == 125
    spend = state["treasury"]["spends"]["spend-1"]
    assert spend["status"] == "executed"
    assert spend["transferred_to"] == "@bob"
    assert spend["transferred_amount"] == 125


def test_treasury_spend_execute_rejects_insufficient_balance_without_marking_executed() -> None:
    state = {
        "height": 10,
        "time": 1,
        "params": {"economic_unlock_time": 0, "economics_enabled": True},
        "accounts": {"@bob": {"balance": 0, "nonce": 0, "poh_tier": 2, "banned": False, "locked": False}},
        "treasury_wallets": {"TREASURY_PROTOCOL": {"wallet_id": "TREASURY_PROTOCOL", "balance": 5}},
        "treasury": {
            "spends": {
                "spend-1": {
                    "spend_id": "spend-1",
                    "treasury_id": "TREASURY_PROTOCOL",
                    "status": "proposed",
                    "allowed_signers": ["@alice"],
                    "threshold": 1,
                    "signatures": {"@alice": {"at_nonce": 1}},
                    "earliest_execute_height": 1,
                    "to": "@bob",
                    "amount": 25,
                    "payload": {"to": "@bob", "amount": 25},
                }
            }
        },
    }

    with pytest.raises(TreasuryApplyError) as excinfo:
        apply_treasury(
            state,
            _env("TREASURY_SPEND_EXECUTE", "SYSTEM", 2, {"spend_id": "spend-1"}, system=True),
        )

    assert excinfo.value.reason == "insufficient_treasury_balance"
    assert state["treasury_wallets"]["TREASURY_PROTOCOL"]["balance"] == 5
    assert state["accounts"]["@bob"]["balance"] == 0
    assert state["treasury"]["spends"]["spend-1"]["status"] == "proposed"


def test_group_treasury_spend_execute_moves_balances() -> None:
    state = {
        "height": 10,
        "time": 1,
        "params": {"economic_unlock_time": 0, "economics_enabled": True},
        "accounts": {"@bob": {"balance": 0, "nonce": 0, "poh_tier": 2, "banned": False, "locked": False}},
        "treasury_wallets": {"TREASURY_GROUP::g1": {"wallet_id": "TREASURY_GROUP::g1", "balance": 300}},
        "group_treasury_spends": {
            "gspend-1": {
                "spend_id": "gspend-1",
                "group_id": "g1",
                "treasury_id": "TREASURY_GROUP::g1",
                "status": "proposed",
                "allowed_signers": ["@alice"],
                "threshold": 1,
                "signatures": {"@alice": {"at_nonce": 1}},
                "earliest_execute_height": 1,
                "to": "@bob",
                "amount": 70,
            }
        },
    }

    result = apply_groups(
        state,
        _env("GROUP_TREASURY_SPEND_EXECUTE", "SYSTEM", 2, {"spend_id": "gspend-1"}, system=True),
    )

    assert result == {
        "applied": "GROUP_TREASURY_SPEND_EXECUTE",
        "spend_id": "gspend-1",
        "to": "@bob",
        "amount": 70,
    }
    assert state["treasury_wallets"]["TREASURY_GROUP::g1"]["balance"] == 230
    assert state["accounts"]["@bob"]["balance"] == 70
    assert state["group_treasury_spends"]["gspend-1"]["status"] == "executed"


def test_group_treasury_spend_execute_rejects_missing_recipient() -> None:
    state = {
        "height": 10,
        "time": 1,
        "params": {"economic_unlock_time": 0, "economics_enabled": True},
        "accounts": {},
        "treasury_wallets": {"TREASURY_GROUP::g1": {"wallet_id": "TREASURY_GROUP::g1", "balance": 300}},
        "group_treasury_spends": {
            "gspend-1": {
                "spend_id": "gspend-1",
                "group_id": "g1",
                "treasury_id": "TREASURY_GROUP::g1",
                "status": "proposed",
                "allowed_signers": ["@alice"],
                "threshold": 1,
                "signatures": {"@alice": {"at_nonce": 1}},
                "earliest_execute_height": 1,
                "to": "@ghost",
                "amount": 70,
            }
        },
    }

    with pytest.raises(GroupsApplyError) as excinfo:
        apply_groups(
            state,
            _env("GROUP_TREASURY_SPEND_EXECUTE", "SYSTEM", 2, {"spend_id": "gspend-1"}, system=True),
        )

    assert excinfo.value.reason == "to_account_missing"
    assert "@ghost" not in state["accounts"]
    assert state["group_treasury_spends"]["gspend-1"]["status"] == "proposed"


def test_reward_distribution_rejects_missing_credit_recipient_without_creating_account() -> None:
    state = {
        "height": 10,
        "time": 1,
        "params": {"economic_unlock_time": 0, "economics_enabled": True},
        "accounts": {MINT_POOL_ACCOUNT_ID: {"balance": 50, "nonce": 0, "poh_tier": 0}},
    }

    with pytest.raises(RewardsApplyError) as excinfo:
        apply_rewards(
            state,
            _env(
                "BLOCK_REWARD_DISTRIBUTE",
                "SYSTEM",
                2,
                {
                    "block_id": "b1",
                    "transfers": [{"to": "@ghost", "amount": 25}],
                    "debits": [{"from": MINT_POOL_ACCOUNT_ID, "amount": 25}],
                },
                system=True,
            ),
        )

    assert excinfo.value.reason == "to_account_missing"
    assert "@ghost" not in state["accounts"]
    assert state["accounts"][MINT_POOL_ACCOUNT_ID]["balance"] == 50


def test_governance_executable_action_must_have_current_canon_schema_even_if_allowlisted() -> None:
    state = {
        "chain_id": "weall-prod",
        "height": 10,
        "params": {
            "mode": "production",
            "gov_action_allowlist": ["TREASURY_PARAMS_SET"],
        },
        "accounts": {"@val": {"poh_tier": 2, "banned": False, "locked": False}},
        "roles": {"validators": {"active_set": ["@val"]}},
    }

    with pytest.raises(ApplyError) as excinfo:
        apply_governance(
            state,
            _env(
                "GOV_PROPOSAL_CREATE",
                "@val",
                1,
                {
                    "proposal_id": "p1",
                    "title": "stale action",
                    "rules": {"start_stage": "voting"},
                    "actions": [{"tx_type": "TREASURY_PARAMS_SET", "payload": {"timelock_blocks": 1}}],
                },
            ),
        )

    assert excinfo.value.code == "forbidden"
    assert excinfo.value.reason == "governance_action_missing_canon_schema"


def test_executable_governance_rejects_non_electorate_vote() -> None:
    state = {
        "chain_id": "weall-prod",
        "height": 10,
        "params": {"mode": "production"},
        "accounts": {
            "@val": {"poh_tier": 2, "banned": False, "locked": False},
            "@outsider": {"poh_tier": 2, "banned": False, "locked": False},
        },
        "roles": {"validators": {"active_set": ["@val"]}},
    }
    apply_governance(
        state,
        _env(
            "GOV_PROPOSAL_CREATE",
            "@val",
            1,
            {
                "proposal_id": "p1",
                "title": "set quorum",
                "rules": {"start_stage": "voting"},
                "actions": [{"tx_type": "GOV_QUORUM_SET", "payload": {"quorum_percent": 67}}],
            },
        ),
    )

    with pytest.raises(ApplyError) as excinfo:
        apply_governance(
            state,
            _env("GOV_VOTE_CAST", "@outsider", 2, {"proposal_id": "p1", "vote": "yes"}),
        )

    assert excinfo.value.reason == "executable_governance_vote_requires_electorate_member"
    assert "@outsider" not in state["gov_proposals_by_id"]["p1"]["votes"]


def test_role_activation_rejects_revoked_role_eligibility() -> None:
    state = {
        "height": 10,
        "accounts": {
            "@alice": {
                "poh_tier": 2,
                "banned": False,
                "locked": False,
                "reputation_milli": 10_000,
            }
        },
        "reputation": {
            "role_eligibility": {
                "@alice": {"roles": {"Juror": False}, "updated_at_nonce": 9}
            }
        },
        "roles": {"jurors": {"by_id": {"@alice": {"enrolled": True}}, "active_set": []}},
    }

    with pytest.raises(RolesApplyError) as excinfo:
        apply_roles(
            state,
            _env("ROLE_JUROR_ACTIVATE", "SYSTEM", 10, {"account_id": "@alice"}, system=True),
        )

    assert excinfo.value.reason == "role_eligibility_revoked"
    assert state["roles"]["jurors"]["active_set"] == []


def test_role_activation_revalidates_current_account_restrictions() -> None:
    state = {
        "height": 10,
        "accounts": {
            "@alice": {
                "poh_tier": 2,
                "banned": True,
                "locked": False,
                "reputation_milli": 10_000,
            }
        },
        "roles": {"node_operators": {"by_id": {"@alice": {"enrolled": True}}, "active_set": []}},
    }

    with pytest.raises(RolesApplyError) as excinfo:
        apply_roles(
            state,
            _env("ROLE_NODE_OPERATOR_ACTIVATE", "SYSTEM", 10, {"account_id": "@alice"}, system=True),
        )

    assert excinfo.value.reason == "account_restricted"
    assert state["roles"]["node_operators"]["active_set"] == []
