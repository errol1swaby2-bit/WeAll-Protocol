from __future__ import annotations

import pytest

from weall.ledger.constants import MAX_SUPPLY, MINT_POOL_ACCOUNT_ID
from weall.runtime.apply.rewards import RewardsApplyError, apply_rewards
from weall.runtime.tx_admission_types import TxEnvelope


def _active_state() -> dict:
    return {
        "time": 1,
        "height": 1,
        "params": {"genesis_time": 0, "economic_unlock_time": 0, "economics_enabled": True},
        "accounts": {
            MINT_POOL_ACCOUNT_ID: {"balance": 0},
            "@validator": {"balance": 0},
            "@operator": {"balance": 0},
            "@juror": {"balance": 0},
            "@creator": {"balance": 0},
            "TREASURY": {"balance": 0},
        },
        "economics": {"monetary_policy": {"issued": 0, "max_supply": MAX_SUPPLY}},
    }


def _locked_state() -> dict:
    st = _active_state()
    st["time"] = 0
    st["params"]["economic_unlock_time"] = 999
    st["params"]["economics_enabled"] = False
    return st


def _sys(tx_type: str, payload: dict, nonce: int = 1) -> TxEnvelope:
    return TxEnvelope(tx_type=tx_type, signer="SYSTEM", nonce=nonce, payload=payload, system=True)


def test_block_reward_mint_is_locked_before_activation_batch485() -> None:
    st = _locked_state()

    with pytest.raises(Exception):
        apply_rewards(st, _sys("BLOCK_REWARD_MINT", {"block_id": "b1", "amount": 100}))

    assert st["accounts"][MINT_POOL_ACCOUNT_ID]["balance"] == 0


def test_block_reward_mint_credits_issuance_and_mint_pool_batch485() -> None:
    st = _active_state()

    res = apply_rewards(st, _sys("BLOCK_REWARD_MINT", {"block_id": "b1", "height": 1, "amount": 100}))

    assert res["applied"] == "BLOCK_REWARD_MINT"
    assert res["deduped"] is False
    assert st["economics"]["monetary_policy"]["issued"] == 100
    assert st["accounts"][MINT_POOL_ACCOUNT_ID]["balance"] == 100
    assert st["rewards"]["stats"]["minted_total"] == 100


def test_block_reward_mint_replay_is_deduped_without_extra_supply_batch485() -> None:
    st = _active_state()
    payload = {"block_id": "b1", "height": 1, "amount": 100}

    first = apply_rewards(st, _sys("BLOCK_REWARD_MINT", payload, nonce=1))
    replay = apply_rewards(st, _sys("BLOCK_REWARD_MINT", payload, nonce=2))

    assert first["deduped"] is False
    assert replay["deduped"] is True
    assert st["economics"]["monetary_policy"]["issued"] == 100
    assert st["accounts"][MINT_POOL_ACCOUNT_ID]["balance"] == 100
    assert st["rewards"]["stats"]["minted_total"] == 100


def test_block_reward_mint_rejects_cap_without_partial_mutation_batch485() -> None:
    st = _active_state()
    st["economics"]["monetary_policy"]["issued"] = MAX_SUPPLY - 10

    with pytest.raises(RewardsApplyError) as ei:
        apply_rewards(st, _sys("BLOCK_REWARD_MINT", {"block_id": "b-cap", "height": 1, "amount": 11}))

    assert ei.value.reason == "mint_exceeds_max_supply"
    assert "b-cap" not in st.get("rewards", {}).get("block_rewards_by_id", {})
    assert st["economics"]["monetary_policy"]["issued"] == MAX_SUPPLY - 10
    assert st["accounts"][MINT_POOL_ACCOUNT_ID]["balance"] == 0


def test_block_reward_distribute_conserves_minted_pool_batch485() -> None:
    st = _active_state()
    apply_rewards(st, _sys("BLOCK_REWARD_MINT", {"block_id": "b2", "height": 2, "amount": 100}, nonce=1))

    payload = {
        "block_id": "b2",
        "transfers": [
            {"to": "@validator", "amount": 20},
            {"to": "@operator", "amount": 20},
            {"to": "@juror", "amount": 20},
            {"to": "@creator", "amount": 20},
            {"to": "TREASURY", "amount": 20},
        ],
        "debits": [{"from": MINT_POOL_ACCOUNT_ID, "amount": 100}],
    }
    res = apply_rewards(st, _sys("BLOCK_REWARD_DISTRIBUTE", payload, nonce=2))

    assert res["distributed_total"] == 100
    assert st["accounts"][MINT_POOL_ACCOUNT_ID]["balance"] == 0
    assert st["accounts"]["@validator"]["balance"] == 20
    assert st["accounts"]["@operator"]["balance"] == 20
    assert st["accounts"]["@juror"]["balance"] == 20
    assert st["accounts"]["@creator"]["balance"] == 20
    assert st["accounts"]["TREASURY"]["balance"] == 20
    assert st["rewards"]["stats"]["distributed_total"] == 100


def test_block_reward_distribute_rejects_unfunded_distribution_batch485() -> None:
    st = _active_state()

    with pytest.raises(RewardsApplyError) as ei:
        apply_rewards(
            st,
            _sys(
                "BLOCK_REWARD_DISTRIBUTE",
                {
                    "block_id": "b-unfunded",
                    "transfers": [{"to": "@validator", "amount": 100}],
                    "debits": [{"from": MINT_POOL_ACCOUNT_ID, "amount": 100}],
                },
            ),
        )

    assert ei.value.reason == "insufficient_funds_for_debit"
    assert st["accounts"]["@validator"]["balance"] == 0


def test_block_reward_distribute_replay_is_deduped_without_double_credit_batch485() -> None:
    st = _active_state()
    apply_rewards(st, _sys("BLOCK_REWARD_MINT", {"block_id": "b3", "height": 3, "amount": 100}, nonce=1))

    payload = {
        "block_id": "b3",
        "transfers": [{"to": "@validator", "amount": 100}],
        "debits": [{"from": MINT_POOL_ACCOUNT_ID, "amount": 100}],
    }

    first = apply_rewards(st, _sys("BLOCK_REWARD_DISTRIBUTE", payload, nonce=2))
    replay = apply_rewards(st, _sys("BLOCK_REWARD_DISTRIBUTE", payload, nonce=3))

    assert first["deduped"] is False
    assert replay["deduped"] is True
    assert st["accounts"]["@validator"]["balance"] == 100
    assert st["accounts"][MINT_POOL_ACCOUNT_ID]["balance"] == 0
    assert st["rewards"]["stats"]["distributed_total"] == 100
