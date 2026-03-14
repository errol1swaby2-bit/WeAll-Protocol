# tests/test_finality_testnet_self_attest.py
from __future__ import annotations

from pathlib import Path

import pytest

from weall.runtime.executor import WeAllExecutor


def _repo_root():
    import pathlib

    return pathlib.Path(__file__).resolve().parents[1]


def test_producer_progresses_only_with_applicable_txs(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Apply semantics smoke:
    - invalid txs do not advance height
    - valid txs advance height
    """
    monkeypatch.setenv("WEALL_UNSAFE_DEV", "1")
    monkeypatch.setenv("WEALL_SIGVERIFY", "0")

    root = _repo_root()
    tx_index_path = str(root / "generated" / "tx_index.json")
    db_path = str(tmp_path / "weall.db")

    ex = WeAllExecutor(db_path=db_path, node_id="@alice", chain_id="apply-smoke", tx_index_path=tx_index_path)

    bad = ex.submit_tx({"tx_type": "ACCOUNT_REGISTER", "nonce": 1, "payload": {}})
    assert bad["ok"] is False

    st0 = ex.read_state()
    h0 = int(st0.get("height", 0))

    meta0 = ex.produce_block(max_txs=10)
    assert meta0.ok is True
    assert meta0.height == h0

    assert ex.submit_tx({"tx_type": "ACCOUNT_REGISTER", "signer": "@user001", "nonce": 1, "payload": {"pubkey": "k:u1"}})["ok"] is True
    meta1 = ex.produce_block(max_txs=10)
    assert meta1.ok is True
    assert meta1.height == h0 + 1
