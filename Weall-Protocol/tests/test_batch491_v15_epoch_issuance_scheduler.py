from __future__ import annotations

from weall.ledger.constants import INITIAL_ISSUANCE_PER_EPOCH, ISSUANCE_EPOCH_BLOCKS, MAX_SUPPLY
from weall.runtime.system_tx_engine import schedule_block_rewards_system_txs


def _state(issued: int = 0) -> dict:
    return {
        "height": 0,
        "time": 1,
        "params": {"genesis_time": 0, "economic_unlock_time": 0, "economics_enabled": True},
        "accounts": {"@validator": {"balance": 0}, "TREASURY": {"balance": 0}},
        "roles": {},
        "economics": {"monetary_policy": {"issued": issued, "max_supply": MAX_SUPPLY}},
        "system_queue": [],
    }


def test_scheduler_does_not_emit_issuance_before_30_block_epoch_boundary_batch491() -> None:
    st = _state()

    schedule_block_rewards_system_txs(st, next_height=ISSUANCE_EPOCH_BLOCKS - 1, proposer="@validator", phase="post")

    assert st["system_queue"] == []


def test_scheduler_emits_one_epoch_issuance_at_30_block_boundary_batch491() -> None:
    st = _state()

    schedule_block_rewards_system_txs(st, next_height=ISSUANCE_EPOCH_BLOCKS, proposer="@validator", phase="post")

    txs = st["system_queue"]
    by_type = {tx["tx_type"]: tx for tx in txs}
    assert set(by_type) == {"BLOCK_REWARD_MINT", "BLOCK_REWARD_DISTRIBUTE"}

    mint_payload = by_type["BLOCK_REWARD_MINT"]["payload"]
    distribute_payload = by_type["BLOCK_REWARD_DISTRIBUTE"]["payload"]
    assert mint_payload["height"] == 30
    assert mint_payload["issuance_epoch"] == 0
    assert mint_payload["epoch_id"] == "issuance_epoch:0"
    assert mint_payload["amount"] == INITIAL_ISSUANCE_PER_EPOCH
    assert distribute_payload["block_id"] == "issuance_epoch:0"
    assert distribute_payload["issuance_epoch"] == 0


def test_scheduler_caps_final_epoch_and_stops_after_max_supply_batch491() -> None:
    almost_cap = _state(issued=MAX_SUPPLY - 7)
    schedule_block_rewards_system_txs(almost_cap, next_height=ISSUANCE_EPOCH_BLOCKS, proposer="@validator", phase="post")
    mint_payload = [tx for tx in almost_cap["system_queue"] if tx["tx_type"] == "BLOCK_REWARD_MINT"][0]["payload"]
    assert mint_payload["amount"] == 7

    capped = _state(issued=MAX_SUPPLY)
    schedule_block_rewards_system_txs(capped, next_height=ISSUANCE_EPOCH_BLOCKS * 2, proposer="@validator", phase="post")
    assert capped["system_queue"] == []


def test_scheduler_remains_locked_until_activation_batch491() -> None:
    st = _state()
    st["time"] = 0
    st["params"]["economic_unlock_time"] = 999
    st["params"]["economics_enabled"] = False

    schedule_block_rewards_system_txs(st, next_height=ISSUANCE_EPOCH_BLOCKS, proposer="@validator", phase="post")

    assert st["system_queue"] == []
