from __future__ import annotations

import multiprocessing as mp
from pathlib import Path

from weall.runtime.sqlite_db import SqliteDB, SqliteLedgerStore


def _worker(db_path: str, n: int) -> None:
    db = SqliteDB(path=db_path)
    db.init_schema()
    store = SqliteLedgerStore(db=db)

    def bump(st: dict) -> None:
        v = st.get("value")
        try:
            iv = int(v)
        except Exception:
            iv = 0
        st["value"] = iv + 1

    for _ in range(int(n)):
        store.update(bump)


def test_sqlite_ledger_store_update_is_cross_process_safe(tmp_path: Path) -> None:
    """Prove SqliteLedgerStore.update() provides a correct cross-process RMW.

    Production-readiness regression test: multiple processes increment
    a shared counter stored inside SQLite. The final value must match exactly.
    """
    db_path = str(tmp_path / "weall_test.db")
    db = SqliteDB(path=db_path)
    db.init_schema()
    store = SqliteLedgerStore(db=db)

    store.write({"value": 0, "height": 0, "tip": ""})

    procs: list[mp.Process] = []
    workers = 4
    per = 250

    for _ in range(workers):
        pr = mp.Process(target=_worker, args=(db_path, per))
        pr.start()
        procs.append(pr)

    for pr in procs:
        pr.join(30)
        assert pr.exitcode == 0

    final = store.read()
    assert int(final.get("value", -1)) == workers * per
