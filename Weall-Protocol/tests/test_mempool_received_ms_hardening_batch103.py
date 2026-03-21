from __future__ import annotations

from pathlib import Path

from weall.runtime.mempool import PersistentMempool
from weall.runtime.sqlite_db import SqliteDB


def _pool(tmp_path: Path) -> PersistentMempool:
    db = SqliteDB(path=str(tmp_path / "mempool.db"))
    return PersistentMempool(db=db, chain_id="weall-test")


def test_mempool_ignores_client_supplied_received_ms(tmp_path: Path) -> None:
    pool = _pool(tmp_path)

    env = {
        "tx_type": "POST_CREATE",
        "signer": "alice",
        "nonce": 1,
        "payload": {"body": "hello"},
        "received_ms": 9_999_999_999_999,
    }

    meta = pool.add(dict(env))
    assert meta["ok"] is True
    assert int(meta["received_ms"]) < 9_999_999_999_999

    stored = pool.peek(limit=1)
    assert len(stored) == 1
    assert int(stored[0]["received_ms"]) == int(meta["received_ms"])
    assert int(stored[0]["received_ms"]) < 9_999_999_999_999


def test_mempool_order_is_not_client_future_stampable(tmp_path: Path) -> None:
    pool = _pool(tmp_path)

    a = pool.add(
        {
            "tx_type": "POST_CREATE",
            "signer": "alice",
            "nonce": 1,
            "payload": {"body": "a"},
            "received_ms": 9_999_999_999_999,
        }
    )
    b = pool.add(
        {
            "tx_type": "POST_CREATE",
            "signer": "alice",
            "nonce": 2,
            "payload": {"body": "b"},
            "received_ms": 1,
        }
    )

    mp = pool.peek(limit=10)
    assert [item["nonce"] for item in mp] == [1, 2]
    assert int(a["received_ms"]) < int(b["received_ms"])
