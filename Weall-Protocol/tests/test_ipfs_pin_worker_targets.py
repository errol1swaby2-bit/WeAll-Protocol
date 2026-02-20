from __future__ import annotations

from pathlib import Path

from weall.storage.ipfs_pin_worker import IpfsPinWorker, IpfsPinWorkerConfig
from weall.runtime.sqlite_db import SqliteDB


def _mk_worker(tmp_path: Path, operator: str, *, dry_run: bool) -> IpfsPinWorker:
    db_path = str(tmp_path / "weall_test.db")
    db = SqliteDB(path=db_path)
    db.init_schema()
    cfg = IpfsPinWorkerConfig(db_path=db_path, operator_account=operator, dry_run=dry_run, max_jobs=200)
    return IpfsPinWorker(cfg)


def test_worker_skips_when_not_targeted(tmp_path: Path) -> None:
    w = _mk_worker(tmp_path, operator="op2", dry_run=True)

    res = w.enqueue_job("cid:demo1", targets=["opX"])  # not us
    assert res["ok"] is True

    stats = w.run_once()
    assert stats["ok"] is True
    assert stats["processed"] == 0
    assert stats["skipped"] == 1
    assert stats["conflicts"] == 0


def test_worker_processes_when_targeted_dry_run(tmp_path: Path) -> None:
    w = _mk_worker(tmp_path, operator="op2", dry_run=True)

    res = w.enqueue_job("cid:demo2", targets=["op2"])
    assert res["ok"] is True

    stats = w.run_once()
    assert stats["ok"] is True
    assert stats["processed"] == 1
    assert stats["skipped"] == 0
    assert stats["conflicts"] == 0

    # Dry-run keeps the row, so it will still be considered on next pass.
    stats2 = w.run_once()
    assert stats2["ok"] is True
    assert stats2["processed"] == 1
    assert stats2["skipped"] == 0
    assert stats2["conflicts"] == 0


def test_worker_processes_and_deletes_when_not_dry_run(tmp_path: Path) -> None:
    w = _mk_worker(tmp_path, operator="op2", dry_run=False)

    res = w.enqueue_job("cid:demo3", targets=["op2"])
    assert res["ok"] is True

    stats = w.run_once()
    assert stats["ok"] is True
    assert stats["processed"] == 1
    assert stats["pinned"] == 1
    assert stats["skipped"] == 0
    assert stats["conflicts"] == 0

    # Not dry-run deletes completed jobs.
    stats2 = w.run_once()
    assert stats2["ok"] is True
    assert stats2["processed"] == 0
    assert stats2["skipped"] == 0
    assert stats2["conflicts"] == 0


def test_worker_detects_cid_conflict(tmp_path: Path) -> None:
    w = _mk_worker(tmp_path, operator="op2", dry_run=True)

    job1 = {"cid": "cid:conflict", "created_ms": 1, "targets": ["op2"]}
    r1 = w.upsert_job(job1)
    assert r1["ok"] is True

    job2 = {"cid": "cid:conflict", "created_ms": 999, "targets": ["op2"], "extra": {"k": "v"}}
    r2 = w.upsert_job(job2)
    assert r2["ok"] is False
    assert r2["error"] == "cid_conflict"

    stats = w.run_once()
    assert stats["ok"] is True
    assert stats["processed"] == 1
    assert stats["conflicts"] == 0
