# tests/test_block_timestamp_policy.py
from __future__ import annotations

from pathlib import Path

import pytest

from weall.runtime.executor import WeAllExecutor


def _repo_root():
    import pathlib

    return pathlib.Path(__file__).resolve().parents[1]


def test_executor_rejects_future_drift_block_timestamp(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """If the persisted tip timestamp is too far in the future, block production must fail-closed.

    NOTE: executor validates tip_ts_ms (not last_block_ts_ms).
    """
    monkeypatch.setenv("WEALL_UNSAFE_DEV", "1")
    monkeypatch.setenv("WEALL_SIGVERIFY", "0")

    root = _repo_root()
    tx_index_path = str(root / "generated" / "tx_index.json")
    db_path = str(tmp_path / "weall.db")

    ex = WeAllExecutor(db_path=db_path, node_id="@alice", chain_id="ts-policy", tx_index_path=tx_index_path)

    sub = ex.submit_tx({"tx_type": "ACCOUNT_REGISTER", "signer": "@user000", "nonce": 1, "payload": {"pubkey": "k:0"}})
    assert sub["ok"] is True

    # Produce one block to establish a real tip timestamp.
    meta = ex.produce_block(max_txs=1)
    assert meta.ok is True
    st1 = ex.read_state()
    assert int(st1.get("height", 0)) == 1

    # Corrupt the snapshot tip timestamp far into the future.
    st1["tip_ts_ms"] = int(st1.get("tip_ts_ms", 0)) + 10_000_000_000

    # Test-only corruption hook: write snapshot directly.
    ex._store.write_state_snapshot(st1)  # type: ignore[attr-defined]

    # Now block production must fail-closed.
    meta2 = ex.produce_block(max_txs=1)
    assert meta2.ok is False

    st2 = ex.read_state()
    assert int(st2.get("height", 0)) == 1
