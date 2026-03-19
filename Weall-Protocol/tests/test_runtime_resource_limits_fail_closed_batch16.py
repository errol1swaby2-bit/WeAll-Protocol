from __future__ import annotations

import pytest


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("WEALL_MEMPOOL_MAX", raising=False)
    monkeypatch.delenv("WEALL_MEMPOOL_EVICT_ON_FULL", raising=False)
    monkeypatch.delenv("WEALL_SQLITE_BUSY_TIMEOUT_MS", raising=False)
    monkeypatch.delenv("WEALL_MAX_PENDING_REMOTE_BLOCKS", raising=False)
    monkeypatch.delenv("WEALL_SYNC_MAX_ROUNDS", raising=False)


def _tx_index_path() -> str:
    return "generated/tx_index.json"


def test_mempool_prod_rejects_invalid_explicit_integer_limit_env(
    monkeypatch: pytest.MonkeyPatch, tmp_path
) -> None:
    monkeypatch.setenv("WEALL_MODE", "prod")
    monkeypatch.setenv("WEALL_MEMPOOL_MAX", "bogus")

    import weall.runtime.mempool as mempool_mod

    db = mempool_mod.SqliteDB(path=str(tmp_path / "mempool.db"))
    with pytest.raises(ValueError, match=r"invalid_integer_env:WEALL_MEMPOOL_MAX"):
        mempool_mod.PersistentMempool(db=db, chain_id="weall")


def test_mempool_prod_rejects_invalid_explicit_boolean_env(
    monkeypatch: pytest.MonkeyPatch, tmp_path
) -> None:
    monkeypatch.setenv("WEALL_MODE", "prod")
    monkeypatch.setenv("WEALL_MEMPOOL_EVICT_ON_FULL", "maybe")

    import weall.runtime.mempool as mempool_mod

    db = mempool_mod.SqliteDB(path=str(tmp_path / "mempool.db"))
    with pytest.raises(ValueError, match=r"invalid_boolean_env:WEALL_MEMPOOL_EVICT_ON_FULL"):
        mempool_mod.PersistentMempool(db=db, chain_id="weall")


def test_mempool_dev_defaults_invalid_explicit_envs(
    monkeypatch: pytest.MonkeyPatch, tmp_path
) -> None:
    monkeypatch.setenv("WEALL_MODE", "dev")
    monkeypatch.setenv("WEALL_MEMPOOL_MAX", "bogus")
    monkeypatch.setenv("WEALL_MEMPOOL_EVICT_ON_FULL", "maybe")

    import weall.runtime.mempool as mempool_mod

    db = mempool_mod.SqliteDB(path=str(tmp_path / "mempool.db"))
    pool = mempool_mod.PersistentMempool(db=db, chain_id="weall")
    assert pool.max_items == 50_000
    assert pool.evict_on_full is False


def test_sqlitedb_prod_rejects_invalid_explicit_timeout_env(
    monkeypatch: pytest.MonkeyPatch, tmp_path
) -> None:
    monkeypatch.setenv("WEALL_MODE", "prod")
    monkeypatch.setenv("WEALL_SQLITE_BUSY_TIMEOUT_MS", "bogus")

    import weall.runtime.sqlite_db as sqlite_mod

    db = sqlite_mod.SqliteDB(path=str(tmp_path / "ledger.db"))
    with pytest.raises(ValueError, match=r"invalid_integer_env:WEALL_SQLITE_BUSY_TIMEOUT_MS"):
        db.init_schema()


def test_sqlitedb_dev_defaults_invalid_explicit_timeout_env(
    monkeypatch: pytest.MonkeyPatch, tmp_path
) -> None:
    monkeypatch.setenv("WEALL_MODE", "dev")
    monkeypatch.setenv("WEALL_SQLITE_BUSY_TIMEOUT_MS", "bogus")

    import weall.runtime.sqlite_db as sqlite_mod

    db = sqlite_mod.SqliteDB(path=str(tmp_path / "ledger.db"))
    db.init_schema()
    assert (tmp_path / "ledger.db").exists()


def test_executor_prod_rejects_invalid_explicit_cache_limit_env(
    monkeypatch: pytest.MonkeyPatch, tmp_path
) -> None:
    monkeypatch.setenv("WEALL_MODE", "prod")
    monkeypatch.setenv("WEALL_MAX_PENDING_REMOTE_BLOCKS", "bogus")

    import weall.runtime.executor as executor_mod

    with pytest.raises(ValueError, match=r"invalid_integer_env:WEALL_MAX_PENDING_REMOTE_BLOCKS"):
        executor_mod.WeAllExecutor(
            db_path=str(tmp_path / "node.db"),
            node_id="@node",
            chain_id="weall",
            tx_index_path=_tx_index_path(),
        )


def test_executor_prod_rejects_invalid_explicit_sync_round_env(
    monkeypatch: pytest.MonkeyPatch, tmp_path
) -> None:
    monkeypatch.setenv("WEALL_MODE", "prod")
    monkeypatch.setenv("WEALL_SYNC_MAX_ROUNDS", "bogus")

    import weall.runtime.executor as executor_mod

    ex = executor_mod.WeAllExecutor(
        db_path=str(tmp_path / "node.db"),
        node_id="@node",
        chain_id="weall",
        tx_index_path=_tx_index_path(),
    )

    class _Peer:
        def request_state_sync(self, *args, **kwargs):
            raise AssertionError("request_state_sync should not run when env parsing fails")

    trusted_anchor = {
        "height": 2,
        "finalized_height": 0,
        "tip_hash": "tip-2",
        "state_root": "state-root-2",
        "finalized_block_id": "",
        "snapshot_hash": "snap-2",
    }
    with pytest.raises(ValueError, match=r"invalid_integer_env:WEALL_SYNC_MAX_ROUNDS"):
        ex.request_and_apply_state_sync(_Peer(), "peer-1", trusted_anchor=trusted_anchor)


def test_executor_dev_defaults_invalid_explicit_cache_limit_env(
    monkeypatch: pytest.MonkeyPatch, tmp_path
) -> None:
    monkeypatch.setenv("WEALL_MODE", "dev")
    monkeypatch.setenv("WEALL_MAX_PENDING_REMOTE_BLOCKS", "bogus")

    import weall.runtime.executor as executor_mod

    ex = executor_mod.WeAllExecutor(
        db_path=str(tmp_path / "node.db"),
        node_id="@node",
        chain_id="weall",
        tx_index_path=_tx_index_path(),
    )
    assert ex._max_pending_remote_blocks == 256
