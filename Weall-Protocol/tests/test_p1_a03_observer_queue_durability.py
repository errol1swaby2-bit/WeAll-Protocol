from __future__ import annotations

import json
import os
import stat
from pathlib import Path

import pytest

from weall.api.routes_public_parts import tx as tx_routes


def test_a03_f002_durable_queue_fsyncs_file_then_rename_then_parent(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    if os.name == "nt":
        pytest.skip("production durability contract is POSIX")

    queue = tmp_path / "observer_tx_queue.json"
    monkeypatch.setenv("WEALL_TX_QUEUE_PATH", str(queue))

    real_fsync = os.fsync
    real_replace = os.replace
    events: list[str] = []

    def traced_fsync(fd: int) -> None:
        mode = os.fstat(fd).st_mode
        events.append("dir_fsync" if stat.S_ISDIR(mode) else "file_fsync")
        real_fsync(fd)

    def traced_replace(src: str | os.PathLike[str], dst: str | os.PathLike[str]) -> None:
        events.append("replace")
        real_replace(src, dst)

    monkeypatch.setattr(tx_routes.os, "fsync", traced_fsync)
    monkeypatch.setattr(tx_routes.os, "replace", traced_replace)

    tx_routes._write_tx_queue_unlocked(
        [
            {
                "tx_id": "tx-a03",
                "created_ms": 1,
                "status": "pending",
                "envelope": {"signer": "@alice", "nonce": 1},
            }
        ]
    )

    assert events == ["file_fsync", "replace", "dir_fsync"]
    payload = json.loads(queue.read_text(encoding="utf-8"))
    assert payload["version"] == 2
    assert payload["records"][0]["tx_id"] == "tx-a03"
    assert not queue.with_suffix(queue.suffix + ".tmp").exists()


def test_a03_f002_file_fsync_failure_prevents_queue_publication(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    queue = tmp_path / "observer_tx_queue.json"
    monkeypatch.setenv("WEALL_TX_QUEUE_PATH", str(queue))

    def fail_fsync(_fd: int) -> None:
        raise OSError("synthetic_file_fsync_failure")

    monkeypatch.setattr(tx_routes.os, "fsync", fail_fsync)

    with pytest.raises(OSError, match="synthetic_file_fsync_failure"):
        tx_routes._write_tx_queue_unlocked(
            [{"tx_id": "tx-fail", "created_ms": 1, "status": "pending"}]
        )

    assert not queue.exists()


def test_a03_f002_directory_fsync_failure_prevents_successful_durable_return(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    if os.name == "nt":
        pytest.skip("production durability contract is POSIX")

    queue = tmp_path / "observer_tx_queue.json"
    monkeypatch.setenv("WEALL_TX_QUEUE_PATH", str(queue))

    real_fsync = os.fsync
    calls = 0

    def fail_directory_fsync(fd: int) -> None:
        nonlocal calls
        calls += 1
        if stat.S_ISDIR(os.fstat(fd).st_mode):
            raise OSError("synthetic_directory_fsync_failure")
        real_fsync(fd)

    monkeypatch.setattr(tx_routes.os, "fsync", fail_directory_fsync)

    with pytest.raises(OSError, match="synthetic_directory_fsync_failure"):
        tx_routes._write_tx_queue_unlocked(
            [{"tx_id": "tx-dir-fail", "created_ms": 1, "status": "pending"}]
        )

    assert calls == 2
    # The rename may already be visible, but the caller receives failure and
    # therefore cannot truthfully acknowledge a durable queue handoff.
    assert queue.exists()
