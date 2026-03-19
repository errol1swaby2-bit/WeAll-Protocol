from __future__ import annotations

from pathlib import Path

import pytest

from weall.runtime.executor import ExecutorError, WeAllExecutor
from weall.runtime.mempool import PersistentMempool, compute_tx_id
from weall.runtime.protocol_profile import GENESIS_CREATED_MS, PROTOCOL_VERSION
from weall.runtime.sqlite_db import SqliteDB


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def _tx_index_path() -> str:
    return str(_repo_root() / "generated" / "tx_index.json")


def test_fresh_genesis_is_deterministic(tmp_path: Path) -> None:
    ex1 = WeAllExecutor(db_path=str(tmp_path / "a.db"), node_id="@n1", chain_id="chain-A", tx_index_path=_tx_index_path())
    ex2 = WeAllExecutor(db_path=str(tmp_path / "b.db"), node_id="@n2", chain_id="chain-A", tx_index_path=_tx_index_path())

    assert ex1.state["created_ms"] == GENESIS_CREATED_MS
    assert ex2.state["created_ms"] == GENESIS_CREATED_MS
    assert ex1.state["meta"]["protocol_version"] == PROTOCOL_VERSION
    assert ex1.state["created_ms"] == ex2.state["created_ms"]


def test_restart_with_protocol_version_mismatch_fails_closed(tmp_path: Path) -> None:
    db_path = str(tmp_path / "weall.db")
    ex = WeAllExecutor(db_path=db_path, node_id="@alice", chain_id="chain-A", tx_index_path=_tx_index_path())
    st = ex.read_state()
    st.setdefault("meta", {})["protocol_version"] = "older-binary"
    ex._ledger_store.write(st)

    with pytest.raises(ExecutorError, match="protocol_version mismatch"):
        WeAllExecutor(db_path=db_path, node_id="@alice", chain_id="chain-A", tx_index_path=_tx_index_path())


def test_executor_mempool_uses_executor_chain_id_not_env(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv("WEALL_CHAIN_ID", "wrong-chain")
    ex = WeAllExecutor(db_path=str(tmp_path / "weall.db"), node_id="@alice", chain_id="chain-A", tx_index_path=_tx_index_path())
    env = {"tx_type": "ACCOUNT_REGISTER", "signer": "@alice", "nonce": 1, "payload": {"pubkey": "k:alice"}}
    added = ex.mempool.add(dict(env))
    assert added["ok"] is True
    assert added["tx_id"] == compute_tx_id(env, chain_id="chain-A")


def test_persistent_mempool_requires_chain_id_without_env(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.delenv("WEALL_CHAIN_ID", raising=False)
    db = SqliteDB(path=str(tmp_path / "mempool.db"))
    with pytest.raises(ValueError, match="requires an explicit chain_id"):
        PersistentMempool(db=db)
