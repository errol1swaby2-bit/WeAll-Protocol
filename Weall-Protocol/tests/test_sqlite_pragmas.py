from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from weall.runtime.sqlite_db import SqliteDB


def _pragma(con: sqlite3.Connection, name: str) -> int | str:
    row = con.execute(f"PRAGMA {name};").fetchone()
    if row is None:
        raise AssertionError(f"missing pragma: {name}")
    # sqlite3.Row behaves like a tuple for PRAGMA single-value results
    return row[0]


def test_sqlite_operational_pragmas_are_applied(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # Force deterministic defaults for this test.
    monkeypatch.setenv("WEALL_MODE", "prod")
    monkeypatch.delenv("WEALL_SQLITE_SYNCHRONOUS", raising=False)
    monkeypatch.setenv("WEALL_SQLITE_BUSY_TIMEOUT_MS", "1234")
    monkeypatch.setenv("WEALL_SQLITE_WAL_AUTOCHECKPOINT", "777")
    monkeypatch.setenv("WEALL_SQLITE_JOURNAL_SIZE_LIMIT", str(8 * 1024 * 1024))
    monkeypatch.setenv("WEALL_SQLITE_CACHE_SIZE_KIB", str(4096))
    monkeypatch.delenv("WEALL_SQLITE_MMAP_SIZE", raising=False)

    db = SqliteDB(path=str(tmp_path / "weall.db"))
    db.init_schema()

    with db.connection() as con:
        jm = str(_pragma(con, "journal_mode")).lower()
        assert jm == "wal"

        # FULL is the prod default.
        sync = int(_pragma(con, "synchronous"))
        assert sync == 2

        assert int(_pragma(con, "foreign_keys")) == 1

        # MEMORY corresponds to 2
        assert int(_pragma(con, "temp_store")) == 2

        assert int(_pragma(con, "busy_timeout")) == 1234
        assert int(_pragma(con, "wal_autocheckpoint")) == 777
        assert int(_pragma(con, "journal_size_limit")) == 8 * 1024 * 1024

        # cache_size negative means KiB; SQLite may return negative.
        cache_sz = int(_pragma(con, "cache_size"))
        assert cache_sz == -4096
