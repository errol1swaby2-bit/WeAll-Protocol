from __future__ import annotations

import copy
from pathlib import Path

import pytest

from weall.runtime.block_history import (
    BLOCK_HISTORY_CHECKPOINT_KEY,
    BlockHistoryRetentionError,
    compact_bounded_block_history_in_place,
    project_bounded_block_history_state,
)
from weall.runtime.executor import WeAllExecutor
from weall.runtime.state_hash import compute_state_root, consensus_state_root_view


def _chain_state(
    height: int,
    *,
    max_records: int = 4,
    finalized_height: int | None = None,
) -> dict:
    blocks: dict[str, dict] = {}
    for h in range(1, int(height) + 1):
        blocks[f"b{h}"] = {
            "height": h,
            "prev_block_id": f"b{h - 1}" if h > 1 else "",
            "block_ts_ms": h * 1_000,
        }
    state: dict = {
        "height": int(height),
        "tip": f"b{height}" if height else "",
        "blocks": blocks,
        "accounts": {},
        "meta": {"consensus_block_history_max_records": int(max_records)},
    }
    if finalized_height is not None:
        state["finalized"] = {
            "height": int(finalized_height),
            "block_id": f"b{finalized_height}",
        }
    return state


def _tx_index_path() -> str:
    return str(Path(__file__).resolve().parents[1] / "generated" / "tx_index.json")


def _executor(tmp_path: Path, name: str) -> WeAllExecutor:
    return WeAllExecutor(
        db_path=str(tmp_path / f"{name}.sqlite"),
        node_id=name,
        chain_id="p0-10-history-test",
        tx_index_path=_tx_index_path(),
    )


def test_root_projection_is_bounded_without_mutating_source() -> None:
    state = _chain_state(6, max_records=4, finalized_height=3)
    before = copy.deepcopy(state)

    view = consensus_state_root_view(state)

    assert state == before
    assert list(view["blocks"].keys()) == ["b3", "b4", "b5", "b6"]
    checkpoint = view[BLOCK_HISTORY_CHECKPOINT_KEY]
    assert checkpoint["records_committed"] == 2
    assert checkpoint["through_height"] == 2
    assert checkpoint["through_block_id"] == "b2"
    assert len(checkpoint["root"]) == 64


def test_compacted_state_has_exact_same_state_root_as_uncompacted_projection() -> None:
    state = _chain_state(8, max_records=4, finalized_height=5)
    projected_root = compute_state_root(state)
    compacted = copy.deepcopy(state)

    removed = compact_bounded_block_history_in_place(compacted)

    assert removed == 4
    assert len(compacted["blocks"]) == 4
    assert compute_state_root(compacted) == projected_root


def test_checkpoint_is_schedule_independent_across_incremental_compaction() -> None:
    one_shot = _chain_state(6, max_records=4, finalized_height=3)
    compact_bounded_block_history_in_place(one_shot)

    incremental = _chain_state(5, max_records=4, finalized_height=2)
    compact_bounded_block_history_in_place(incremental)
    incremental["finalized"] = {"height": 3, "block_id": "b3"}
    incremental["blocks"]["b6"] = {
        "height": 6,
        "prev_block_id": "b5",
        "block_ts_ms": 6_000,
    }
    incremental["height"] = 6
    incremental["tip"] = "b6"
    compact_bounded_block_history_in_place(incremental)

    assert incremental["blocks"] == one_shot["blocks"]
    assert incremental[BLOCK_HISTORY_CHECKPOINT_KEY] == one_shot[BLOCK_HISTORY_CHECKPOINT_KEY]
    assert compute_state_root(incremental) == compute_state_root(one_shot)


def test_compaction_requires_root_visible_finalized_anchor() -> None:
    state = _chain_state(6, max_records=4)

    with pytest.raises(
        BlockHistoryRetentionError,
        match="block_history_compaction_requires_finalized_anchor",
    ):
        project_bounded_block_history_state(state)


def test_finality_lag_fails_closed_instead_of_pruning_live_safety_ancestry() -> None:
    state = _chain_state(6, max_records=4, finalized_height=2)

    with pytest.raises(
        BlockHistoryRetentionError,
        match="block_history_window_exhausted_by_live_safety_ancestry",
    ):
        project_bounded_block_history_state(state)


def test_local_bft_metadata_cannot_change_application_compaction_root() -> None:
    left = _chain_state(6, max_records=4, finalized_height=3)
    right = copy.deepcopy(left)
    left["bft"] = {
        "view": 19,
        "finalized_block_id": "b1",
        "high_qc": {"block_id": "b6"},
        "locked_qc": {"block_id": "b5"},
    }
    right["bft"] = {
        "view": 77,
        "finalized_block_id": "other-local-id",
        "high_qc": {"block_id": "pending-X"},
        "locked_qc": {"block_id": "pending-Y"},
    }

    assert project_bounded_block_history_state(left)["blocks"] == (
        project_bounded_block_history_state(right)["blocks"]
    )
    assert compute_state_root(left) == compute_state_root(right)


def test_malformed_checkpoint_fails_closed() -> None:
    state = _chain_state(6, max_records=4, finalized_height=3)
    state[BLOCK_HISTORY_CHECKPOINT_KEY] = {
        "version": 1,
        "records_committed": 2,
        "through_height": 2,
        "through_block_id": "b2",
        "root": "not-a-hash",
    }

    with pytest.raises(BlockHistoryRetentionError, match="checkpoint_root_invalid"):
        project_bounded_block_history_state(state)


def test_leader_follower_and_restart_share_bounded_history_root(
    tmp_path: Path, monkeypatch
) -> None:
    monkeypatch.setenv("WEALL_MODE", "test")
    monkeypatch.setenv("WEALL_BFT_ENABLED", "0")
    monkeypatch.setenv("WEALL_REQUIRE_VRF", "0")

    leader = _executor(tmp_path, "leader")
    follower = _executor(tmp_path, "follower")
    for ex in (leader, follower):
        ex.state.setdefault("meta", {})["consensus_block_history_max_records"] = 3

    for _ in range(6):
        current_height = int(leader.state.get("height") or 0)
        if current_height >= 3:
            finalized_height = current_height - 1
            ordered = sorted(
                (
                    (int(rec.get("height") or 0), str(block_id))
                    for block_id, rec in leader.state.get("blocks", {}).items()
                    if isinstance(rec, dict)
                )
            )
            by_height = {height: block_id for height, block_id in ordered}
            finalized = {
                "height": finalized_height,
                "block_id": by_height[finalized_height],
            }
            leader.state["finalized"] = dict(finalized)
            follower.state["finalized"] = dict(finalized)

        produced = leader.produce_block(max_txs=1, allow_empty=True)
        assert produced.ok is True, produced.error
        block = leader.get_latest_block()
        assert isinstance(block, dict)
        applied = follower.apply_block(copy.deepcopy(block))
        assert applied.ok is True, applied.error
        assert len(leader.state.get("blocks") or {}) <= 3
        assert len(follower.state.get("blocks") or {}) <= 3
        assert compute_state_root(leader.state) == compute_state_root(follower.state)

    expected_root = compute_state_root(follower.state)
    expected_checkpoint = copy.deepcopy(follower.state.get(BLOCK_HISTORY_CHECKPOINT_KEY))
    restarted = _executor(tmp_path, "follower")

    assert len(restarted.state.get("blocks") or {}) <= 3
    assert restarted.state.get(BLOCK_HISTORY_CHECKPOINT_KEY) == expected_checkpoint
    assert compute_state_root(restarted.state) == expected_root
