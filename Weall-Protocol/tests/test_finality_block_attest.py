# tests/test_finality_block_attest.py
from __future__ import annotations

from pathlib import Path

import pytest

from weall.runtime.executor import WeAllExecutor


def _repo_root():
    import pathlib

    return pathlib.Path(__file__).resolve().parents[1]


def test_block_retrieval_and_tip_persistence(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Persistence invariant:
    - blocks retrievable by height
    - tip survives restarts
    """
    monkeypatch.setenv("WEALL_UNSAFE_DEV", "1")
    monkeypatch.setenv("WEALL_SIGVERIFY", "0")

    root = _repo_root()
    tx_index_path = str(root / "generated" / "tx_index.json")
    db_path = str(tmp_path / "weall.db")

    ex = WeAllExecutor(db_path=db_path, node_id="@alice", chain_id="blocks", tx_index_path=tx_index_path)

    assert ex.submit_tx({"tx_type": "ACCOUNT_REGISTER", "signer": "@user001", "nonce": 1, "payload": {"pubkey": "k:u1"}})["ok"] is True
    meta = ex.produce_block(max_txs=1)
    assert meta.ok is True
    assert meta.height == 1

    blk = ex.get_block_by_height(1)
    assert blk is not None

    # Restart and ensure tip persists.
    ex2 = WeAllExecutor(db_path=db_path, node_id="@alice", chain_id="blocks", tx_index_path=tx_index_path)
    st2 = ex2.read_state()
    assert int(st2.get("height", 0)) == 1
