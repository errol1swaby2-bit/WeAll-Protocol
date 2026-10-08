from __future__ import annotations

import copy
from pathlib import Path

from weall.ledger.constants import (
    HALVING_INTERVAL_ISSUANCE_EPOCHS,
    INITIAL_ISSUANCE_PER_EPOCH,
    MAX_SUPPLY,
)
from weall.ledger.issuance import (
    epoch_issuance_subsidy_atomic,
    issuance_epoch_index_for_due_height,
    issuance_height_for_epoch,
)
from weall.runtime.executor import WeAllExecutor
from weall.runtime.system_tx_engine import schedule_block_rewards_system_txs


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def _state(*, enabled: bool, issued: int = 0) -> dict:
    return {
        "height": 0,
        "time": 1,
        "chain_id": "a11-genesis-relative-local",
        "params": {
            "genesis_time": 0,
            "economic_unlock_time": 0,
            "economics_enabled": enabled,
        },
        "accounts": {
            "@validator": {"balance": 0},
            "TREASURY": {"balance": 0},
        },
        "roles": {
            "node_operators": {"active_set": []},
            "jurors": {"active_set": []},
            "creators": {"active_set": []},
        },
        "economics": {
            "monetary_policy": {
                "issued": issued,
                "max_supply": MAX_SUPPLY,
            }
        },
        "system_queue": [],
    }


def _schedule(state: dict, epoch: int) -> list[dict]:
    height = issuance_height_for_epoch(epoch)
    schedule_block_rewards_system_txs(
        state,
        next_height=height,
        proposer="@validator",
        phase="post",
    )
    return list(state["system_queue"])


def _mint_payload(queue: list[dict]) -> dict:
    rows = [row for row in queue if row["tx_type"] == "BLOCK_REWARD_MINT"]
    assert len(rows) == 1
    return dict(rows[0]["payload"])


def test_a11_f003_genesis_relative_activation_boundaries() -> None:
    first_halved_epoch = HALVING_INTERVAL_ISSUANCE_EPOCHS
    last_full_epoch = first_halved_epoch - 1

    before = _state(enabled=True)
    before_mint = _mint_payload(_schedule(before, last_full_epoch))
    assert before_mint["issuance_epoch"] == last_full_epoch
    assert before_mint["amount"] == INITIAL_ISSUANCE_PER_EPOCH

    exact = _state(enabled=True)
    exact_mint = _mint_payload(_schedule(exact, first_halved_epoch))
    assert exact_mint["issuance_epoch"] == first_halved_epoch
    assert exact_mint["amount"] == INITIAL_ISSUANCE_PER_EPOCH // 2

    later = _state(enabled=True)
    later_mint = _mint_payload(_schedule(later, first_halved_epoch + 17))
    assert later_mint["issuance_epoch"] == first_halved_epoch + 17
    assert later_mint["amount"] == INITIAL_ISSUANCE_PER_EPOCH // 2

    assert issuance_epoch_index_for_due_height(
        issuance_height_for_epoch(first_halved_epoch)
    ) == first_halved_epoch
    assert (
        epoch_issuance_subsidy_atomic(first_halved_epoch)
        == INITIAL_ISSUANCE_PER_EPOCH // 2
    )


def test_a11_f003_locked_epochs_are_skipped_not_backfilled() -> None:
    first_halved_epoch = HALVING_INTERVAL_ISSUANCE_EPOCHS
    locked = _state(enabled=False)

    assert _schedule(locked, first_halved_epoch - 1) == []
    assert _schedule(locked, first_halved_epoch) == []

    locked["params"]["economics_enabled"] = True
    queue = _schedule(locked, first_halved_epoch + 1)
    mint = _mint_payload(queue)

    assert mint["issuance_epoch"] == first_halved_epoch + 1
    assert mint["amount"] == INITIAL_ISSUANCE_PER_EPOCH // 2
    assert mint["amount"] != INITIAL_ISSUANCE_PER_EPOCH
    assert len([row for row in queue if row["tx_type"] == "BLOCK_REWARD_MINT"]) == 1


def test_a11_f003_two_node_replay_and_cap_are_deterministic() -> None:
    epoch = HALVING_INTERVAL_ISSUANCE_EPOCHS + 9
    first = _state(enabled=True)
    second = copy.deepcopy(first)

    first_queue = _schedule(first, epoch)
    second_queue = _schedule(second, epoch)
    assert first_queue == second_queue

    capped = _state(enabled=True, issued=MAX_SUPPLY - 7)
    capped_mint = _mint_payload(_schedule(capped, epoch))
    assert capped_mint["amount"] == 7


def test_a11_f003_restart_and_state_sync_preserve_genesis_relative_origin(
    tmp_path: Path,
) -> None:
    epoch = HALVING_INTERVAL_ISSUANCE_EPOCHS + 3
    committed_height = issuance_height_for_epoch(epoch) - 1
    tx_index_path = str(_repo_root() / "generated" / "tx_index.json")

    source_db = str(tmp_path / "source.db")
    source = WeAllExecutor(
        db_path=source_db,
        node_id="@validator",
        chain_id="a11-genesis-relative-local",
        tx_index_path=tx_index_path,
    )
    state = source.read_state()
    state.update(_state(enabled=True))
    state["height"] = committed_height
    source.state = state
    source._ledger_store.write(source.state)

    restarted = WeAllExecutor(
        db_path=source_db,
        node_id="@validator",
        chain_id="a11-genesis-relative-local",
        tx_index_path=tx_index_path,
    )
    restarted_state = restarted.read_state()
    assert restarted_state["height"] == committed_height

    synced_db = str(tmp_path / "synced.db")
    synced = WeAllExecutor(
        db_path=synced_db,
        node_id="@validator",
        chain_id="a11-genesis-relative-local",
        tx_index_path=tx_index_path,
    )
    synced.state = copy.deepcopy(restarted_state)
    synced._ledger_store.write(synced.state)

    reopened_sync = WeAllExecutor(
        db_path=synced_db,
        node_id="@validator",
        chain_id="a11-genesis-relative-local",
        tx_index_path=tx_index_path,
    )
    synced_state = reopened_sync.read_state()
    assert synced_state["height"] == committed_height

    source_queue = _schedule(restarted_state, epoch)
    synced_queue = _schedule(synced_state, epoch)
    assert source_queue == synced_queue

    mint = _mint_payload(source_queue)
    assert mint["issuance_epoch"] == epoch
    assert mint["amount"] == INITIAL_ISSUANCE_PER_EPOCH // 2
