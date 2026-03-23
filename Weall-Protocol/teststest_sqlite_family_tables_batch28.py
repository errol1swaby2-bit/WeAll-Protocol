from __future__ import annotations

import sqlite3

from weall.runtime.sqlite_db import SqliteDB


def test_sqlite_schema_creates_family_and_helper_tables_batch28(tmp_path) -> None:
    db = SqliteDB(path=str(tmp_path / "weall.sqlite"))
    db.init_schema()
    con = sqlite3.connect(str(tmp_path / "weall.sqlite"))
    try:
        names = {row[0] for row in con.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()}
    finally:
        con.close()
    assert "state_consensus" in names
    assert "state_content" in names
    assert "tx_conflict_materialization" in names
    assert "helper_plans" in names
    assert "helper_resolution_journal" in names
