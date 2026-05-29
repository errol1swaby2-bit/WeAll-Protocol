from __future__ import annotations

from weall.api.routes_public_parts.economics import economics_status_from_state
from weall.ledger.tokenomics import (
    COIN,
    HALVING_INTERVAL_BLOCKS,
    INITIAL_BLOCK_REWARD,
    MAX_SUPPLY,
    REWARD_BUCKET_BPS,
    block_subsidy_atomic,
    next_halving_height,
    tokenomics_policy_from_state,
)


def test_real_tokenomics_policy_is_supply_capped_and_locked_batch481() -> None:
    state = {
        "height": 0,
        "time": 1,
        "params": {
            "genesis_time": 1,
            "economic_unlock_time": 999999,
            "economics_enabled": False,
        },
        "accounts": {
            "@alice": {"balance": 0},
            "TREASURY": {"balance": 0},
        },
        "economics": {
            "monetary_policy": {
                "issued": 0,
            }
        },
    }

    policy = tokenomics_policy_from_state(state)

    assert policy["name"] == "WeCoin"
    assert policy["symbol"] == "WCN"
    assert policy["precision"]["atomic_units_per_coin"] == COIN
    assert policy["supply"]["max_supply_atomic"] == MAX_SUPPLY
    assert policy["supply"]["issued_atomic"] == 0
    assert policy["supply"]["remaining_issuance_atomic"] == MAX_SUPPLY
    assert policy["activation"]["locked"] is True
    assert policy["activation"]["enabled"] is False
    assert policy["activation"]["activation_tx_type"] == "ECONOMICS_ACTIVATION"
    assert policy["emission"]["next_block_subsidy_atomic"] == INITIAL_BLOCK_REWARD
    assert policy["emission"]["supply_cap_enforced"] is True


def test_real_tokenomics_halving_schedule_batch481() -> None:
    assert block_subsidy_atomic(0) == 0
    assert block_subsidy_atomic(1) == INITIAL_BLOCK_REWARD
    assert block_subsidy_atomic(HALVING_INTERVAL_BLOCKS - 1) == INITIAL_BLOCK_REWARD
    assert block_subsidy_atomic(HALVING_INTERVAL_BLOCKS) == INITIAL_BLOCK_REWARD // 2
    assert block_subsidy_atomic(HALVING_INTERVAL_BLOCKS * 2) == INITIAL_BLOCK_REWARD // 4

    assert next_halving_height(0) == HALVING_INTERVAL_BLOCKS
    assert next_halving_height(HALVING_INTERVAL_BLOCKS) == HALVING_INTERVAL_BLOCKS * 2


def test_real_tokenomics_reward_split_is_equal_twenty_percent_batch481() -> None:
    assert REWARD_BUCKET_BPS == {
        "validators": 2000,
        "operators": 2000,
        "jurors": 2000,
        "creators": 2000,
        "treasury": 2000,
    }
    assert sum(REWARD_BUCKET_BPS.values()) == 10_000


def test_economics_status_exposes_real_tokenomics_batch481() -> None:
    state = {
        "height": 10,
        "time": 1,
        "params": {
            "genesis_time": 1,
            "economic_unlock_time": 999999,
            "economics_enabled": False,
        },
        "accounts": {
            "@alice": {"balance": 123},
        },
        "economics": {
            "monetary_policy": {
                "issued": 456,
            },
            "fee_policy": {},
        },
    }

    status = economics_status_from_state(state, account="@alice")

    assert status["ok"] is True
    assert status["locked"] is True
    assert status["tokenomics"]["name"] == "WeCoin"
    assert status["tokenomics"]["supply"]["issued_atomic"] == 456
    assert status["tokenomics"]["activation"]["locked"] is True
    assert "governance_votes" in status["tokenomics"]["fee_free_action_classes"]
