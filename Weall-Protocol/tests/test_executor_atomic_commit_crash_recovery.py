# tests/test_executor_atomic_commit_crash_recovery.py
from __future__ import annotations

from pathlib import Path

import pytest

from weall.runtime.executor import WeAllExecutor


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def test_executor_atomic_commit_rolls_back_on_mid_commit_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Production invariant: block insert + mempool cleanup + snapshot must be atomic.

    We simulate a failure after inserting the block row but before writing
    the ledger_state snapshot. With atomic commit, *nothing* from the commit
    should be persisted.
    """

    root = _repo_root()
    tx_index_path = str(root / "generated" / "tx_index.json")
    db_path = str(tmp_path / "weall.db")

    ex = WeAllExecutor(
        db_path=db_path, node_id="@alice", chain_id="crash-test", tx_index_path=tx_index_path
    )

    # Put at least one tx in the mempool so the candidate is non-empty.
    sub = ex.submit_tx(
        {
            "tx_type": "ACCOUNT_REGISTER",
            "signer": "@user0",
            "nonce": 1,
            "payload": {"pubkey": "k:0"},
        }
    )
    assert sub["ok"] is True

    blk, st2, applied_ids, invalid_ids, err = ex.build_block_candidate(max_txs=1, allow_empty=False)
    assert err == ""

    # Fail after block insert, before writing snapshot.
    monkeypatch.setenv("WEALL_MODE", "test")
    monkeypatch.setenv("WEALL_TEST_FAIL_AFTER_BLOCK_INSERT", "1")
    meta = ex.commit_block_candidate(
        block=blk, new_state=st2, applied_ids=applied_ids, invalid_ids=invalid_ids
    )
    assert meta.ok is False

    # On restart, there should be no blocks and height==0, and mempool still has the tx.
    ex2 = WeAllExecutor(
        db_path=db_path, node_id="@alice", chain_id="crash-test", tx_index_path=tx_index_path
    )
    st = ex2.read_state()
    assert int(st.get("height", 0)) == 0

    mp = ex2.read_mempool()
    assert len(mp) == 1


def test_post_commit_housekeeping_failure_reports_durable_truth_and_halts_executor(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A post-transaction failure must never masquerade as a rolled-back block."""

    monkeypatch.setenv("WEALL_MODE", "test")
    root = _repo_root()
    tx_index_path = str(root / "generated" / "tx_index.json")
    db_path = str(tmp_path / "post-commit.db")

    ex = WeAllExecutor(
        db_path=db_path,
        node_id="@alice",
        chain_id="post-commit-truth",
        tx_index_path=tx_index_path,
    )
    block, new_state, applied_ids, invalid_ids, err = ex.build_block_candidate(
        max_txs=0,
        allow_empty=True,
        force_ts_ms=1,
    )
    assert err == ""
    assert isinstance(block, dict)
    assert isinstance(new_state, dict)

    def _boom(_state) -> None:
        raise RuntimeError("synthetic_post_commit_bft_reload_failure")

    monkeypatch.setattr(ex._bft, "load_from_state", _boom)

    meta = ex.commit_block_candidate(
        block=block,
        new_state=new_state,
        applied_ids=applied_ids,
        invalid_ids=invalid_ids,
    )

    assert meta.ok is True
    assert meta.height == 1
    assert meta.block_id == str(block["block_id"])
    assert meta.error == (
        "post_commit_housekeeping_failed:RuntimeError:synthetic_post_commit_bft_reload_failure"
    )
    assert int(ex.state.get("height") or 0) == 1
    assert ex.block_loop_unhealthy is True
    assert ex._validator_signing_enabled is False

    with ex._db.connection() as con:
        block_row = con.execute("SELECT height, block_id FROM blocks WHERE height=1;").fetchone()
        ledger_row = con.execute("SELECT height, block_id FROM ledger_state WHERE id=1;").fetchone()
    assert block_row is not None
    assert int(block_row["height"]) == 1
    assert str(block_row["block_id"]) == str(block["block_id"])
    assert ledger_row is not None
    assert int(ledger_row["height"]) == 1
    assert str(ledger_row["block_id"]) == str(block["block_id"])

    block2, state2, applied2, invalid2, err2 = ex.build_block_candidate(
        max_txs=0,
        allow_empty=True,
        force_ts_ms=2,
    )
    assert block2 is None
    assert state2 is None
    assert applied2 == []
    assert invalid2 == []
    assert err2.startswith("executor_unhealthy:post_commit_housekeeping_failed:RuntimeError:")

    replay_meta = ex.apply_block(dict(block))
    assert replay_meta.ok is False
    assert replay_meta.error.startswith(
        "executor_unhealthy:post_commit_housekeeping_failed:RuntimeError:"
    )
    assert replay_meta.height == 1
    assert replay_meta.block_id == str(block["block_id"])

    # The in-process fail-closed latch is deliberately restart-scoped. Restart
    # must recover from the durable ledger truth rather than retrying height 1.
    restarted = WeAllExecutor(
        db_path=db_path,
        node_id="@alice",
        chain_id="post-commit-truth",
        tx_index_path=tx_index_path,
    )
    assert int(restarted.read_state().get("height") or 0) == 1
    assert not getattr(restarted, "_post_commit_housekeeping_error", "")
