"""PR62 family-level runtime observations, NOT constitutional authorization.

These tests invoke domain apply handlers, not a two-node BFT rehearsal.
They do not authenticate SYSTEM provenance, determine normative applicability,
or close any authority review queue item.
"""

from __future__ import annotations

import copy

import pytest

from weall.runtime.apply.content import ContentApplyError, apply_content
from weall.runtime.apply.reputation import (
    REP_MIN_UNITS,
    ReputationApplyError,
    apply_reputation,
)
from weall.runtime.apply.rewards import RewardsApplyError, apply_rewards
from weall.runtime.tx_admission import TxEnvelope


def _tx(
    tx_type: str,
    payload: dict,
    *,
    signer: str = "SYSTEM",
    nonce: int = 1,
    system: bool = True,
) -> TxEnvelope:
    return TxEnvelope(
        tx_type=tx_type,
        signer=signer,
        nonce=nonce,
        payload=payload,
        system=system,
        parent="pr62:synthetic-parent" if system else None,
        sig="fixture-not-authenticated",
    )


def _account(**updates: object) -> dict:
    account = {
        "nonce": 3,
        "poh_tier": 2,
        "banned": False,
        "locked": False,
        "reputation": "0",
        "reputation_milli": 0,
        "balance": 700,
        "keys": [],
    }
    account.update(updates)
    return account


def _economic_state() -> dict:
    return {
        "time": 1,
        "height": 30,
        "params": {
            "genesis_time": 0,
            "economic_unlock_time": 0,
            "economics_enabled": True,
        },
        "accounts": {
            "@source": _account(balance=100),
            "@recipient": _account(balance=5),
            "@other": _account(balance=7),
        },
    }


def test_pr62_content_reaction_account_changes_only_nonce_on_system_apply() -> None:
    state = {"accounts": {"@author": _account()}}
    before = copy.deepcopy(state["accounts"]["@author"])
    result = apply_content(
        state,
        _tx(
            "CONTENT_REACTION_SET",
            {"target_id": "post:fixture", "reaction": "like"},
            signer="@author",
            nonce=4,
        ),
    )
    assert result is not None and result["applied"] == "CONTENT_REACTION_SET"
    assert state["accounts"]["@author"] == {**before, "nonce": 4}
    assert len(state["content"]["reactions"]) == 1


def test_pr62_content_banned_account_denied_before_nonce_or_post_mutation() -> None:
    state = {"accounts": {"@author": _account(banned=True)}}
    before = copy.deepcopy(state)
    with pytest.raises(ContentApplyError) as exc:
        apply_content(
            state,
            _tx(
                "CONTENT_POST_CREATE",
                {"post_id": "p:denied", "body": "denied"},
                signer="@author",
                nonce=4,
                system=False,
            ),
        )
    assert exc.value.reason == "account_banned"
    assert state == before


@pytest.mark.parametrize("tx_type", ["ACCOUNT_BAN", "ACCOUNT_REINSTATE"])
def test_pr62_reputation_exclusion_receipts_require_system_marker_without_mutation(
    tx_type: str,
) -> None:
    state = {"accounts": {"@target": _account()}}
    before = copy.deepcopy(state)
    with pytest.raises(ReputationApplyError) as exc:
        apply_reputation(
            state,
            _tx(
                tx_type,
                {"account_id": "@target", "reason": "fixture"},
                signer="@attacker",
                system=False,
            ),
        )
    assert exc.value.reason == "system_only"
    assert state == before


def test_pr62_ban_reinstate_replay_preserves_balance_nonce_and_reputation() -> None:
    state = {"accounts": {"@target": _account()}}
    baseline = copy.deepcopy(state["accounts"]["@target"])
    ban_payload = {"account_id": "@target", "reason": "fixture-ban"}
    first = apply_reputation(state, _tx("ACCOUNT_BAN", ban_payload, nonce=1))
    assert first is not None and first["deduped"] is False
    assert state["accounts"]["@target"]["banned"] is True
    replay = apply_reputation(state, _tx("ACCOUNT_BAN", ban_payload, nonce=1))
    assert replay is not None and replay["deduped"] is True
    assert state["reputation"]["bans"]["@target"]["banned"] is True

    unban_payload = {"account_id": "@target", "reason": "fixture-reinstatement"}
    second = apply_reputation(state, _tx("ACCOUNT_REINSTATE", unban_payload, nonce=2))
    assert second is not None and second["deduped"] is False
    assert state["accounts"]["@target"]["banned"] is False
    replay_second = apply_reputation(
        state, _tx("ACCOUNT_REINSTATE", unban_payload, nonce=2)
    )
    assert replay_second is not None and replay_second["deduped"] is True
    assert state["reputation"]["bans"]["@target"]["banned"] is False
    for field in ("balance", "nonce", "poh_tier", "reputation_milli"):
        assert state["accounts"]["@target"][field] == baseline[field]


def test_pr62_reputation_floor_auto_ban_replay_does_not_double_apply() -> None:
    state = {"accounts": {"@target": _account()}}
    payload = {
        "account_id": "@target",
        "delta_id": "pr62:floor",
        "delta_milli": REP_MIN_UNITS,
        "reason": "fixture-synthetic-floor",
    }
    first = apply_reputation(state, _tx("REPUTATION_DELTA_APPLY", payload))
    assert first is not None and first["newly_banned"] is True
    assert state["accounts"]["@target"]["banned"] is True
    assert state["accounts"]["@target"]["reputation_milli"] == REP_MIN_UNITS
    before = copy.deepcopy(state)
    replay = apply_reputation(
        state, _tx("REPUTATION_DELTA_APPLY", payload, nonce=2)
    )
    assert replay is not None and replay["deduped"] is True
    assert state["accounts"]["@target"] == before["accounts"]["@target"]
    assert len(state["reputation"]["deltas"]) == 1


def test_pr62_reward_distribution_conserves_balances_and_dedupes_replay() -> None:
    state = _economic_state()
    before_total = sum(acct["balance"] for acct in state["accounts"].values())
    payload = {
        "block_id": "pr62:funded-distribution",
        "transfers": [
            {"to": "@recipient", "amount": 20},
            {"to": "@other", "amount": 10},
        ],
        "debits": [{"from": "@source", "amount": 30}],
    }
    first = apply_rewards(state, _tx("BLOCK_REWARD_DISTRIBUTE", payload))
    assert first is not None and first["deduped"] is False
    assert first["distributed_total"] == first["debited_total"] == 30
    assert {
        key: value["balance"] for key, value in state["accounts"].items()
    } == {"@source": 70, "@recipient": 25, "@other": 17}
    assert sum(acct["balance"] for acct in state["accounts"].values()) == before_total
    snapshot = copy.deepcopy(state["accounts"])
    replay = apply_rewards(
        state, _tx("BLOCK_REWARD_DISTRIBUTE", payload, nonce=2)
    )
    assert replay is not None and replay["deduped"] is True
    assert state["accounts"] == snapshot


@pytest.mark.parametrize(
    ("transfers", "debits", "reason"),
    [
        ([{"to": "@missing", "amount": 10}], [{"from": "@source", "amount": 10}],
         "to_account_missing"),
        ([{"to": "@recipient", "amount": 200}], [{"from": "@source", "amount": 200}],
         "insufficient_funds_for_debit"),
        ([{"to": "@recipient", "amount": 30}], [],
         "distribution_exceeds_debits"),
    ],
)
def test_pr62_reward_failed_preflight_does_not_change_account_balances(
    transfers: list[dict], debits: list[dict], reason: str
) -> None:
    state = _economic_state()
    before = copy.deepcopy(state["accounts"])
    with pytest.raises(RewardsApplyError) as exc:
        apply_rewards(
            state,
            _tx(
                "BLOCK_REWARD_DISTRIBUTE",
                {"block_id": "pr62:rejected", "transfers": transfers, "debits": debits},
            ),
        )
    assert exc.value.reason == reason
    assert state["accounts"] == before
