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
from weall.net.messages import MsgType, StateSyncResponseMsg, WireHeader
from weall.net.state_sync import build_snapshot_anchor
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

    assert (
        issuance_epoch_index_for_due_height(issuance_height_for_epoch(first_halved_epoch))
        == first_halved_epoch
    )
    assert epoch_issuance_subsidy_atomic(first_halved_epoch) == INITIAL_ISSUANCE_PER_EPOCH // 2


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


def _enable_local_economics(state: dict) -> None:
    params = state.setdefault("params", {})
    params["genesis_time"] = 0
    params["economic_unlock_time"] = 0
    params["economics_enabled"] = True
    state.setdefault("accounts", {}).setdefault("@validator", {"balance": 0})
    state["accounts"].setdefault("TREASURY", {"balance": 0})
    roles = state.setdefault("roles", {})
    roles.setdefault("node_operators", {"active_set": []})
    roles.setdefault("jurors", {"active_set": []})
    roles.setdefault("creators", {"active_set": []})
    state.setdefault("economics", {}).setdefault(
        "monetary_policy", {"issued": 0, "max_supply": MAX_SUPPLY}
    )
    state["system_queue"] = []


def test_a11_f003_restart_and_state_sync_preserve_genesis_relative_origin(
    tmp_path: Path,
) -> None:
    epoch = HALVING_INTERVAL_ISSUANCE_EPOCHS + 3
    tx_index_path = str(_repo_root() / "generated" / "tx_index.json")
    chain_id = "a11-genesis-relative-sync"

    source_db = str(tmp_path / "source.db")
    source = WeAllExecutor(
        db_path=source_db,
        node_id="@source",
        chain_id=chain_id,
        tx_index_path=tx_index_path,
    )
    submitted = source.submit_tx(
        {
            "tx_type": "ACCOUNT_REGISTER",
            "signer": "@u1",
            "nonce": 1,
            "payload": {"pubkey": "k:@u1"},
        }
    )
    assert submitted["ok"] is True
    assert source.produce_block(max_txs=1).ok is True
    assert int(source.state.get("height") or 0) == 1

    block = source.get_block_by_height(1)
    assert isinstance(block, dict)
    synced_block = dict(block)
    synced_block["parent_block_id"] = str(synced_block.get("prev_block_id") or "")

    lagger_db = str(tmp_path / "lagger.db")
    lagger = WeAllExecutor(
        db_path=lagger_db,
        node_id="@lagger",
        chain_id=chain_id,
        tx_index_path=tx_index_path,
    )
    response = StateSyncResponseMsg(
        header=WireHeader(
            type=MsgType.STATE_SYNC_RESPONSE,
            chain_id=chain_id,
            schema_version="1",
            tx_index_hash=source._tx_index_hash,
            sent_ts_ms=0,
            corr_id="a11-f003",
        ),
        ok=True,
        reason=None,
        height=1,
        snapshot=None,
        blocks=(synced_block,),
        snapshot_hash=None,
        snapshot_anchor=build_snapshot_anchor(source.state),
    )
    metas = lagger.apply_state_sync_response(
        response,
        trusted_anchor=build_snapshot_anchor(source.state),
    )
    assert [meta.ok for meta in metas] == [True]
    assert int(lagger.state.get("height") or 0) == 1

    restarted_source = WeAllExecutor(
        db_path=source_db,
        node_id="@source",
        chain_id=chain_id,
        tx_index_path=tx_index_path,
    )
    restarted_lagger = WeAllExecutor(
        db_path=lagger_db,
        node_id="@lagger",
        chain_id=chain_id,
        tx_index_path=tx_index_path,
    )
    source_state = restarted_source.read_state()
    lagger_state = restarted_lagger.read_state()

    assert int(source_state.get("height") or 0) == 1
    assert int(lagger_state.get("height") or 0) == 1
    assert str(source_state.get("tip") or "") == str(lagger_state.get("tip") or "")

    # Genesis-relative epoch origin is not mutable activation state. After a
    # real restart and real state-sync replay, the same future canonical height
    # therefore derives the same epoch/subsidy on both nodes.
    _enable_local_economics(source_state)
    _enable_local_economics(lagger_state)
    source_queue = _schedule(source_state, epoch)
    lagger_queue = _schedule(lagger_state, epoch)
    assert source_queue == lagger_queue

    mint = _mint_payload(source_queue)
    assert mint["issuance_epoch"] == epoch
    assert mint["amount"] == INITIAL_ISSUANCE_PER_EPOCH // 2
