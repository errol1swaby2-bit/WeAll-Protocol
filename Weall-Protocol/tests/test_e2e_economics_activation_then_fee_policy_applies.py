# tests/test_e2e_economics_activation_then_fee_policy_applies.py
from __future__ import annotations

from pathlib import Path

import pytest

from weall.runtime.executor import ExecutorError, WeAllExecutor


def _repo_root():
    import pathlib

    return pathlib.Path(__file__).resolve().parents[1]


def test_refuse_to_mix_chain_ids_in_same_db(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """SQLite migration safety: chain_id mismatch must fail closed."""
    monkeypatch.setenv("WEALL_UNSAFE_DEV", "1")
    monkeypatch.setenv("WEALL_SIGVERIFY", "0")

    root = _repo_root()
    tx_index_path = str(root / "generated" / "tx_index.json")
    db_path = str(tmp_path / "weall.db")

    ex = WeAllExecutor(db_path=db_path, node_id="@alice", chain_id="A", tx_index_path=tx_index_path)
    assert ex.submit_tx({"tx_type": "ACCOUNT_REGISTER", "signer": "@user000", "nonce": 1, "payload": {"pubkey": "k:u0"}})["ok"] is True
    assert ex.produce_block(max_txs=1).ok is True

    with pytest.raises(ExecutorError):
        WeAllExecutor(db_path=db_path, node_id="@alice", chain_id="B", tx_index_path=tx_index_path)
