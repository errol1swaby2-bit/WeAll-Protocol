from __future__ import annotations

from pathlib import Path

import pytest

from weall.runtime.executor import ExecutorError, WeAllExecutor

ROOT = Path(__file__).resolve().parents[1]
TX_INDEX = ROOT / "generated" / "tx_index.json"


def _executor(tmp_path: Path, name: str) -> WeAllExecutor:
    return WeAllExecutor(
        db_path=str(tmp_path / f"{name}.db"),
        node_id=f"@{name}",
        chain_id=f"a03-{name}",
        tx_index_path=str(TX_INDEX),
    )


def _commit_empty_block(ex: WeAllExecutor, *, ts_ms: int) -> None:
    block, new_state, applied_ids, invalid_ids, err = ex.build_block_candidate(
        max_txs=0,
        allow_empty=True,
        force_ts_ms=ts_ms,
    )
    assert err == ""
    assert isinstance(block, dict)
    assert isinstance(new_state, dict)
    meta = ex.commit_block_candidate(
        block=block,
        new_state=new_state,
        applied_ids=applied_ids,
        invalid_ids=invalid_ids,
    )
    assert meta.ok is True, meta.error


def _ledger_row(ex: WeAllExecutor) -> tuple[int, str, str, int]:
    with ex._db.connection() as con:
        row = con.execute(
            "SELECT height, block_id, state_json, updated_ts_ms "
            "FROM ledger_state WHERE id=1"
        ).fetchone()
    assert row is not None
    return (
        int(row["height"]),
        str(row["block_id"]),
        str(row["state_json"]),
        int(row["updated_ts_ms"]),
    )


def _restore_ledger_row(ex: WeAllExecutor, row: tuple[int, str, str, int]) -> None:
    height, block_id, state_json, updated_ts_ms = row
    with ex._db.write_tx() as con:
        con.execute(
            "UPDATE ledger_state "
            "SET height=?, block_id=?, state_json=?, updated_ts_ms=? "
            "WHERE id=1",
            (height, block_id, state_json, updated_ts_ms),
        )


def test_a03_f001_fresh_database_and_normal_multiblock_restart_pass(tmp_path: Path) -> None:
    fresh = _executor(tmp_path, "normal")
    assert int(fresh.state.get("height") or 0) == 0

    _commit_empty_block(fresh, ts_ms=1_000)
    _commit_empty_block(fresh, ts_ms=2_000)

    restarted = _executor(tmp_path, "normal")
    assert int(restarted.state.get("height") or 0) == 2
    assert restarted.get_block_by_height(2) is not None


def test_a03_f001_zero_snapshot_with_persisted_block_fails_closed(tmp_path: Path) -> None:
    ex = _executor(tmp_path, "zero-behind")
    genesis_row = _ledger_row(ex)
    assert genesis_row[0] == 0

    _commit_empty_block(ex, ts_ms=1_000)
    _restore_ledger_row(ex, genesis_row)

    with pytest.raises(
        ExecutorError,
        match=r"snapshot height 0 but persisted blocks exist up to 1",
    ):
        _executor(tmp_path, "zero-behind")


def test_a03_f001_nonzero_snapshot_behind_newer_blocks_fails_closed(tmp_path: Path) -> None:
    ex = _executor(tmp_path, "stale")
    _commit_empty_block(ex, ts_ms=1_000)
    height_one = _ledger_row(ex)
    assert height_one[0] == 1

    _commit_empty_block(ex, ts_ms=2_000)
    assert int(ex.state.get("height") or 0) == 2
    _restore_ledger_row(ex, height_one)

    with pytest.raises(
        ExecutorError,
        match=r"snapshot height 1 trails max persisted block height 2",
    ):
        _executor(tmp_path, "stale")


def test_a03_f001_snapshot_ahead_of_block_history_fails_closed(tmp_path: Path) -> None:
    ex = _executor(tmp_path, "ahead")
    _commit_empty_block(ex, ts_ms=1_000)
    _commit_empty_block(ex, ts_ms=2_000)
    assert _ledger_row(ex)[0] == 2

    with ex._db.write_tx() as con:
        block = con.execute(
            "SELECT block_id FROM blocks WHERE height=2"
        ).fetchone()
        assert block is not None
        block_id = str(block["block_id"])
        con.execute("DELETE FROM block_hash_index WHERE block_id=?", (block_id,))
        con.execute("DELETE FROM blocks WHERE height=2")

    with pytest.raises(
        ExecutorError,
        match=r"snapshot height 2 exceeds max persisted block height 1",
    ):
        _executor(tmp_path, "ahead")
