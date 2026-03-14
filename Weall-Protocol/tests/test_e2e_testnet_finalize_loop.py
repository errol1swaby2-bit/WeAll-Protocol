# tests/test_e2e_testnet_finalize_loop.py
from __future__ import annotations

from pathlib import Path

import pytest

from weall.runtime.executor import WeAllExecutor


def _repo_root():
    import pathlib

    return pathlib.Path(__file__).resolve().parents[1]


def test_restart_loop_produces_append_only_blocks(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Restart + persistence smoke: height must be monotonic and blocks append-only."""
    monkeypatch.setenv("WEALL_UNSAFE_DEV", "1")
    monkeypatch.setenv("WEALL_SIGVERIFY", "0")

    root = _repo_root()
    tx_index_path = str(root / "generated" / "tx_index.json")
    db_path = str(tmp_path / "weall.db")

    ex = WeAllExecutor(db_path=db_path, node_id="@alice", chain_id="loop", tx_index_path=tx_index_path)

    for i in range(3):
        assert ex.submit_tx(
            {"tx_type": "ACCOUNT_REGISTER", "signer": f"@user{i:03d}", "nonce": 1, "payload": {"pubkey": f"k:user{i:03d}"}}
        )["ok"] is True

    for _ in range(3):
        assert ex.produce_block(max_txs=1).ok is True

    st1 = ex.read_state()
    h1 = int(st1.get("height", 0))
    assert h1 == 3

    # Re-open and ensure height persists, then produce another block.
    ex2 = WeAllExecutor(db_path=db_path, node_id="@alice", chain_id="loop", tx_index_path=tx_index_path)
    st2 = ex2.read_state()
    assert int(st2.get("height", 0)) == 3

    assert ex2.produce_block(max_txs=10).ok is True
    st3 = ex2.read_state()
    assert int(st3.get("height", 0)) == 3  # no new txs => no height change
