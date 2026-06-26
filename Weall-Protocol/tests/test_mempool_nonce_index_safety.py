from __future__ import annotations

import json
import sqlite3
from pathlib import Path

import pytest

from weall.runtime.mempool import PersistentMempool, compute_tx_id
from weall.runtime.sqlite_db import SqliteDB, _canon_json


def _db(tmp_path: Path, name: str = "mempool.db") -> SqliteDB:
    return SqliteDB(path=str(tmp_path / name))


def test_startup_migrates_legacy_mempool_nonce_column_and_backfills_batch110(tmp_path: Path) -> None:
    db_path = tmp_path / "legacy_mempool.db"
    con = sqlite3.connect(str(db_path))
    try:
        con.execute(
            """
            CREATE TABLE mempool (
              tx_id TEXT PRIMARY KEY,
              envelope_json TEXT NOT NULL,
              signer TEXT NOT NULL,
              tx_type TEXT NOT NULL,
              received_ms INTEGER NOT NULL,
              expires_ms INTEGER NOT NULL
            );
            """
        )
        env = {
            "tx_type": "ACCOUNT_REGISTER",
            "signer": "@legacy",
            "nonce": 7,
            "payload": {"pubkey": "k:legacy:7"},
            "chain_id": "weall-test",
        }
        tx_id = compute_tx_id(env, chain_id="weall-test")
        env_persist = dict(env)
        env_persist["tx_id"] = tx_id
        env_persist["received_ms"] = 100
        env_persist["expires_ms"] = 10_000
        con.execute(
            """
            INSERT INTO mempool(tx_id, envelope_json, signer, tx_type, received_ms, expires_ms)
            VALUES(?, ?, ?, ?, ?, ?);
            """,
            (
                tx_id,
                _canon_json(env_persist),
                "@legacy",
                "ACCOUNT_REGISTER",
                100,
                10_000,
            ),
        )
        con.commit()
    finally:
        con.close()

    pool = PersistentMempool(db=SqliteDB(path=str(db_path)), chain_id="weall-test")
    assert pool.size() == 1

    with pool.db.connection() as con2:
        cols = {
            str(row["name"]): row
            for row in con2.execute("PRAGMA table_info(mempool);").fetchall()
        }
        assert "nonce" in cols
        row = con2.execute(
            "SELECT signer, nonce FROM mempool WHERE tx_id=? LIMIT 1;",
            (tx_id,),
        ).fetchone()
        assert row is not None
        assert str(row["signer"]) == "@legacy"
        assert int(row["nonce"]) == 7


def test_startup_fails_closed_on_legacy_nonce_conflict_corruption_batch110(tmp_path: Path) -> None:
    db_path = tmp_path / "legacy_conflict.db"
    con = sqlite3.connect(str(db_path))
    try:
        con.execute(
            """
            CREATE TABLE mempool (
              tx_id TEXT PRIMARY KEY,
              envelope_json TEXT NOT NULL,
              signer TEXT NOT NULL,
              tx_type TEXT NOT NULL,
              received_ms INTEGER NOT NULL,
              expires_ms INTEGER NOT NULL
            );
            """
        )
        base = {
            "tx_type": "ACCOUNT_REGISTER",
            "signer": "@corrupt",
            "nonce": 5,
            "chain_id": "weall-test",
        }
        env1 = {**base, "payload": {"pubkey": "k:corrupt:one"}}
        env2 = {**base, "payload": {"pubkey": "k:corrupt:two"}}
        for idx, env in enumerate((env1, env2), start=1):
            tx_id = compute_tx_id(env, chain_id="weall-test")
            env_persist = dict(env)
            env_persist["tx_id"] = tx_id
            env_persist["received_ms"] = idx
            env_persist["expires_ms"] = 10_000 + idx
            con.execute(
                """
                INSERT INTO mempool(tx_id, envelope_json, signer, tx_type, received_ms, expires_ms)
                VALUES(?, ?, ?, ?, ?, ?);
                """,
                (
                    tx_id,
                    _canon_json(env_persist),
                    "@corrupt",
                    "ACCOUNT_REGISTER",
                    idx,
                    10_000 + idx,
                ),
            )
        con.commit()
    finally:
        con.close()

    with pytest.raises(ValueError, match="mempool_nonce_backfill_conflict:@corrupt:5"):
        PersistentMempool(db=SqliteDB(path=str(db_path)), chain_id="weall-test")


def test_new_mempool_rows_persist_nonce_and_db_unique_index_rejects_duplicate_batch110(
    tmp_path: Path,
) -> None:
    pool = PersistentMempool(db=_db(tmp_path, "fresh.db"), chain_id="weall-test")
    tx = {
        "tx_type": "ACCOUNT_REGISTER",
        "signer": "@alice",
        "nonce": 1,
        "payload": {"pubkey": "k:alice:1"},
    }
    accepted = pool.add(dict(tx))
    assert accepted.get("ok") is True
    tx_id = str(accepted.get("tx_id"))

    with pool.db.connection() as con:
        row = con.execute(
            "SELECT signer, nonce FROM mempool WHERE tx_id=? LIMIT 1;",
            (tx_id,),
        ).fetchone()
        assert row is not None
        assert str(row["signer"]) == "@alice"
        assert int(row["nonce"]) == 1

    duplicate_env = dict(tx)
    duplicate_env["payload"] = {"pubkey": "k:alice:other"}
    duplicate_tx_id = compute_tx_id(duplicate_env, chain_id="weall-test")
    env_persist = dict(duplicate_env)
    env_persist["tx_id"] = duplicate_tx_id
    env_persist["received_ms"] = 999
    env_persist["expires_ms"] = 9_999

    with pytest.raises(sqlite3.IntegrityError):
        with pool.db.write_tx() as con:
            con.execute(
                """
                INSERT INTO mempool(
                    tx_id, envelope_json, signer, tx_type, nonce, received_ms, expires_ms
                )
                VALUES(?, ?, ?, ?, ?, ?, ?);
                """,
                (
                    duplicate_tx_id,
                    json.dumps(env_persist, sort_keys=True),
                    "@alice",
                    "ACCOUNT_REGISTER",
                    1,
                    999,
                    9_999,
                ),
            )
