from __future__ import annotations

import contextlib
import multiprocessing
import os
import threading
import time
from pathlib import Path

import pytest

from weall.api.routes_public_parts import poh as poh_routes
from weall.runtime.block_loop import BlockLoopConfig, BlockProducerLoop
from weall.runtime.executor import WeAllExecutor


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


class _LoopExecutor:
    def __init__(self) -> None:
        self.block_loop_running = False
        self.block_loop_unhealthy = False
        self.block_loop_last_error = ""
        self.block_loop_consecutive_failures = 0
        self.block_loop_shutdown_timeout = False
        self.state = {}


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


def test_block_loop_stop_timeout_retains_generation_ownership(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    entered = threading.Event()
    release = threading.Event()
    executor = _LoopExecutor()
    lock_path = str(tmp_path / "block-loop.lock")
    loop = BlockProducerLoop(
        executor=executor,
        mempool=object(),
        attestation_pool=object(),
        cfg=_loop_config(lock_path),
    )

    def _blocked_run() -> None:
        entered.set()
        release.wait(timeout=10.0)

    monkeypatch.setattr(loop, "_run", _blocked_run)

    assert loop.start() is True
    assert entered.wait(timeout=2.0)

    started = time.monotonic()
    loop.stop()
    elapsed = time.monotonic() - started

    assert elapsed >= 1.8
    assert loop.started is True
    assert executor.block_loop_shutdown_timeout is True

    # A restart on the same object must fail closed while the old worker lives.
    assert loop.start() is False

    # A second producer object also cannot take the singleton file lock.
    contender = BlockProducerLoop(
        executor=_LoopExecutor(),
        mempool=object(),
        attestation_pool=object(),
        cfg=_loop_config(lock_path),
    )
    assert contender.start() is False

    release.set()
    deadline = time.monotonic() + 3.0
    while loop.started and time.monotonic() < deadline:
        time.sleep(0.01)
    assert loop.started is False
    assert executor.block_loop_running is False

    # Clean ownership handoff works only after the old generation is dead.
    monkeypatch.setattr(loop, "_run", lambda: None)
    assert loop.start() is True
    deadline = time.monotonic() + 2.0
    while loop.started and time.monotonic() < deadline:
        time.sleep(0.01)
    assert loop.started is False


def test_tx_status_uses_one_snapshot_during_pending_to_confirmed_commit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    ex = WeAllExecutor(
        db_path=str(tmp_path / "weall.db"),
        node_id="@alice",
        chain_id="p2-tx-status",
        tx_index_path=str(_repo_root() / "generated" / "tx_index.json"),
    )
    submitted = ex.submit_tx(
        {
            "tx_type": "ACCOUNT_REGISTER",
            "signer": "@alice",
            "nonce": 1,
            "payload": {"pubkey": "k:alice"},
        }
    )
    assert submitted["ok"] is True
    tx_id = str(submitted["tx_id"])
    assert ex.get_tx_status(tx_id)["status"] == "pending"

    original_connection = ex._db.connection
    triggered = False

    class _CursorProxy:
        def __init__(self, cursor) -> None:
            self._cursor = cursor

        def fetchone(self):
            nonlocal triggered
            row = self._cursor.fetchone()
            if not triggered:
                triggered = True
                # Commit after the first confirmed lookup has observed absence.
                # The active BEGIN in get_tx_status must keep the subsequent
                # mempool lookup on the pre-commit snapshot.
                monkeypatch.setattr(ex._db, "connection", original_connection)
                produced = ex.produce_block(max_txs=1)
                assert produced.ok is True
            return row

    class _ConnectionProxy:
        def __init__(self, connection) -> None:
            self._connection = connection

        def execute(self, sql, params=()):
            cursor = self._connection.execute(sql, params)
            if "FROM tx_index" in str(sql) and tx_id in tuple(params):
                return _CursorProxy(cursor)
            return cursor

    @contextlib.contextmanager
    def _controlled_connection():
        with original_connection() as connection:
            yield _ConnectionProxy(connection)

    monkeypatch.setattr(ex._db, "connection", _controlled_connection)
    raced = ex.get_tx_status(tx_id)

    assert triggered is True
    assert raced["status"] == "pending"
    monkeypatch.setattr(ex._db, "connection", original_connection)
    assert ex.get_tx_status(tx_id)["status"] == "confirmed"


def _queue_writer(path: str, prefix: str, count: int) -> None:
    os.environ["WEALL_MODE"] = "test"
    os.environ["WEALL_WEBRTC_SIGNAL_QUEUE_PATH"] = path
    os.environ["WEALL_WEBRTC_SIGNAL_QUEUE_MAX_ROWS"] = "5000"
    os.environ["WEALL_WEBRTC_SIGNAL_QUEUE_TTL_MS"] = str(24 * 60 * 60 * 1000)
    for index in range(count):
        row = {
            "tx_queue_id": f"{prefix}:{index}",
            "created_ms": int(time.time() * 1000),
            "payload": {"signal": {"session_id": f"{prefix}:{index}"}},
        }
        with poh_routes._webrtc_signal_queue_lock():
            rows = poh_routes._load_webrtc_signal_queue_unlocked()
            rows.append(row)
            poh_routes._write_webrtc_signal_queue_unlocked(rows)


@pytest.mark.skipif(os.name == "nt", reason="production queue locking is POSIX")
def test_webrtc_queue_two_process_rmw_has_no_lost_rows(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    queue_path = tmp_path / "webrtc-queue.json"
    monkeypatch.setenv("WEALL_MODE", "test")
    monkeypatch.setenv("WEALL_WEBRTC_SIGNAL_QUEUE_PATH", str(queue_path))
    monkeypatch.setenv("WEALL_WEBRTC_SIGNAL_QUEUE_MAX_ROWS", "5000")
    monkeypatch.setenv("WEALL_WEBRTC_SIGNAL_QUEUE_TTL_MS", str(24 * 60 * 60 * 1000))

    ctx = multiprocessing.get_context("fork")
    workers = [
        ctx.Process(target=_queue_writer, args=(str(queue_path), "a", 500)),
        ctx.Process(target=_queue_writer, args=(str(queue_path), "b", 500)),
    ]
    for worker in workers:
        worker.start()
    for worker in workers:
        worker.join(timeout=60)
        assert worker.exitcode == 0

    with poh_routes._webrtc_signal_queue_lock():
        rows = poh_routes._load_webrtc_signal_queue_unlocked()

    ids = [str(row.get("tx_queue_id") or "") for row in rows]
    assert len(ids) == 1000
    assert len(set(ids)) == 1000

    # A stale partial temp file from an interrupted writer is safely replaced
    # under the same lock on the next successful write.
    tmp = queue_path.with_suffix(queue_path.suffix + ".tmp")
    tmp.write_text("{partial", encoding="utf-8")
    with poh_routes._webrtc_signal_queue_lock():
        poh_routes._write_webrtc_signal_queue_unlocked(rows)
    assert not tmp.exists()
    with poh_routes._webrtc_signal_queue_lock():
        assert len(poh_routes._load_webrtc_signal_queue_unlocked()) == 1000
