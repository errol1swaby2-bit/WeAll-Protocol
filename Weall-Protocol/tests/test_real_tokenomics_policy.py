from __future__ import annotations

from weall.api.routes_public_parts.economics import economics_status_from_state
from weall.ledger.tokenomics import (
    COIN,
    HALVING_INTERVAL_ISSUANCE_EPOCHS,
    INITIAL_ISSUANCE_PER_EPOCH,
    ISSUANCE_EPOCH_BLOCKS,
    ISSUANCE_EPOCH_SECONDS,
    MAX_SUPPLY,
    REWARD_BUCKET_BPS,
    TARGET_BLOCK_INTERVAL_SECONDS,
    block_subsidy_atomic,
    epoch_issuance_subsidy_atomic,
    issuance_due_at_height,
    issuance_epoch_index_for_due_height,
    issuance_epoch_index_for_height,
    issuance_height_for_epoch,
    next_halving_issuance_epoch,
    tokenomics_policy_from_state,
)


def test_real_tokenomics_policy_is_supply_capped_epoch_based_and_locked_batch481() -> None:
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

    emission = policy["emission"]
    assert emission["issuance_model"] == "epoch_based"
    assert emission["per_block_issuance"] is False
    assert emission["target_block_interval_seconds"] == TARGET_BLOCK_INTERVAL_SECONDS == 20
    assert emission["issuance_epoch_seconds"] == ISSUANCE_EPOCH_SECONDS == 600
    assert emission["issuance_epoch_blocks"] == ISSUANCE_EPOCH_BLOCKS == 30
    assert emission["initial_epoch_issuance_atomic"] == INITIAL_ISSUANCE_PER_EPOCH
    assert emission["halving_interval_issuance_epochs"] == HALVING_INTERVAL_ISSUANCE_EPOCHS
    assert emission["next_issuance_height"] == 30
    assert emission["next_issuance_epoch"] == 0
    assert emission["next_epoch_issuance_atomic"] == INITIAL_ISSUANCE_PER_EPOCH
    assert emission["supply_cap_enforced"] is True
    assert emission["duplicate_epoch_issuance_invalid"] is True


def test_real_tokenomics_epoch_calculation_and_30_blocks_per_epoch_batch481() -> None:
    assert TARGET_BLOCK_INTERVAL_SECONDS == 20
    assert ISSUANCE_EPOCH_SECONDS == 10 * 60
    assert ISSUANCE_EPOCH_BLOCKS == 30

    assert issuance_epoch_index_for_height(0) == -1
    assert issuance_epoch_index_for_height(1) == 0
    assert issuance_epoch_index_for_height(30) == 0
    assert issuance_epoch_index_for_height(31) == 1
    assert issuance_epoch_index_for_height(60) == 1

    assert issuance_due_at_height(29) is False
    assert issuance_due_at_height(30) is True
    assert issuance_due_at_height(31) is False
    assert issuance_due_at_height(60) is True
    assert issuance_epoch_index_for_due_height(30) == 0
    assert issuance_epoch_index_for_due_height(60) == 1
    assert issuance_height_for_epoch(0) == 30
    assert issuance_height_for_epoch(1) == 60


def test_real_tokenomics_epoch_halving_schedule_batch481() -> None:
    assert epoch_issuance_subsidy_atomic(0) == INITIAL_ISSUANCE_PER_EPOCH
    assert epoch_issuance_subsidy_atomic(1) == INITIAL_ISSUANCE_PER_EPOCH
    assert epoch_issuance_subsidy_atomic(HALVING_INTERVAL_ISSUANCE_EPOCHS - 1) == INITIAL_ISSUANCE_PER_EPOCH
    assert epoch_issuance_subsidy_atomic(HALVING_INTERVAL_ISSUANCE_EPOCHS) == INITIAL_ISSUANCE_PER_EPOCH // 2
    assert epoch_issuance_subsidy_atomic(HALVING_INTERVAL_ISSUANCE_EPOCHS * 2) == INITIAL_ISSUANCE_PER_EPOCH // 4

    assert next_halving_issuance_epoch(0) == HALVING_INTERVAL_ISSUANCE_EPOCHS
    assert next_halving_issuance_epoch(HALVING_INTERVAL_ISSUANCE_EPOCHS) == HALVING_INTERVAL_ISSUANCE_EPOCHS * 2

    # Compatibility wrapper emits no per-block subsidy except at epoch boundaries.
    assert block_subsidy_atomic(1) == 0
    assert block_subsidy_atomic(29) == 0
    assert block_subsidy_atomic(30) == INITIAL_ISSUANCE_PER_EPOCH


def test_real_tokenomics_reward_split_is_equal_twenty_percent_batch481() -> None:
    assert REWARD_BUCKET_BPS == {
        "validators": 2000,
        "operators": 2000,
        "jurors": 2000,
        "creators": 2000,
        "treasury": 2000,
    }
    assert sum(REWARD_BUCKET_BPS.values()) == 10_000


def test_economics_status_exposes_real_epoch_tokenomics_batch481() -> None:
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
    assert status["tokenomics"]["emission"]["issuance_model"] == "epoch_based"
    assert "governance_votes" in status["tokenomics"]["fee_free_action_classes"]
