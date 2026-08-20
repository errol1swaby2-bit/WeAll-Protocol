from __future__ import annotations

import time

import pytest

from weall.runtime.block_loop import (
    BlockLoopConfig,
    BlockProducerLoop,
    _active_validators_from_executor,
)
from weall.runtime.mempool import PersistentMempool
from weall.runtime.sqlite_db import SqliteDB


def test_mempool_candidate_selection_db_failure_is_not_silently_empty(
    monkeypatch: pytest.MonkeyPatch, tmp_path
) -> None:
    monkeypatch.setenv("WEALL_MODE", "prod")
    mempool = PersistentMempool(
        db=SqliteDB(path=str(tmp_path / "mempool.db")),
        chain_id="weall-test",
    )

    def _boom(*, candidate_height: int, limit: int):
        raise RuntimeError("forced_candidate_read_failure")

    monkeypatch.setattr(mempool, "_load_candidate_rows_canonical", _boom)

    with pytest.raises(RuntimeError, match="forced_candidate_read_failure"):
        mempool.fetch_for_block(
            limit=10,
            policy="canonical",
            candidate_height=1,
        )


class _LoopExecutor:
    def __init__(self) -> None:
        self.block_loop_running = False
        self.block_loop_unhealthy = False
        self.block_loop_last_error = ""
        self.block_loop_consecutive_failures = 0
        self.state = {
            "consensus": {"validator_set": {"active_set": ["@canonical"]}},
            "roles": {"validators": {"active_set": ["@stale"]}},
            "bft": {"view": 0},
        }


def _loop_config(lock_path: str) -> BlockLoopConfig:
    return BlockLoopConfig(
        interval_ms=250,
        produce_empty_blocks=False,
        enabled=True,
        lock_path=lock_path,
        max_block_txs=10,
        fail_fast_after=3,
        error_backoff_min_ms=50,
        error_backoff_max_ms=50,
        bft_enabled=False,
        bft_timeout_ms=1000,
        bft_unsafe_autocommit=False,
        validator_account="",
    )


def test_block_loop_thread_exit_clears_started_and_releases_lock(
    monkeypatch: pytest.MonkeyPatch, tmp_path
) -> None:
    executor = _LoopExecutor()
    loop = BlockProducerLoop(
        executor=executor,
        mempool=object(),
        attestation_pool=object(),
        cfg=_loop_config(str(tmp_path / "block-loop.lock")),
    )

    monkeypatch.setattr(loop, "_run", lambda: None)

    assert loop.start() is True
    deadline = time.time() + 2.0
    while loop.started and time.time() < deadline:
        time.sleep(0.01)

    assert loop.started is False
    assert executor.block_loop_running is False

    # The dead thread must not strand the process-wide file lock or stop event.
    assert loop.start() is True
    deadline = time.time() + 2.0
    while loop.started and time.time() < deadline:
        time.sleep(0.01)
    assert loop.started is False


def test_block_loop_normal_stop_can_be_restarted(tmp_path) -> None:
    executor = _LoopExecutor()
    loop = BlockProducerLoop(
        executor=executor,
        mempool=object(),
        attestation_pool=object(),
        cfg=_loop_config(str(tmp_path / "block-loop.lock")),
    )

    assert loop.start() is True
    loop.stop()
    assert loop.started is False
    assert executor.block_loop_running is False

    assert loop.start() is True
    loop.stop()
    assert loop.started is False


def test_block_loop_validator_helper_uses_explicit_consensus_set() -> None:
    executor = _LoopExecutor()
    assert _active_validators_from_executor(executor) == ["@canonical"]

    executor.state["consensus"]["validator_set"]["active_set"] = []
    assert _active_validators_from_executor(executor) == []

    del executor.state["consensus"]["validator_set"]
    assert _active_validators_from_executor(executor) == ["@stale"]
