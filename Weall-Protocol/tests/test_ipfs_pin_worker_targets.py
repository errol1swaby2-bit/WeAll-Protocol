from __future__ import annotations

from pathlib import Path

from weall.storage.ipfs_pin_worker import IpfsPinWorker, IpfsPinWorkerConfig


def _mk_worker(tmp_path: Path, *, operator: str, dry_run: bool) -> IpfsPinWorker:
    db_path = str(tmp_path / "weall.db")
    cfg = IpfsPinWorkerConfig(
        db_path=db_path,
        operator_account=operator,
        dry_run=dry_run,
        max_jobs=50,
        ipfs_enabled=False,  # force deterministic offline behavior for tests
    )
    return IpfsPinWorker(cfg)


def test_worker_skips_jobs_not_targeted_to_operator(tmp_path: Path) -> None:
    w = _mk_worker(tmp_path, operator="op1", dry_run=True)

    res = w.enqueue_job("cid:demo1", targets=["someone-else"])
    assert res["ok"] is True

    stats = w.run_once()
    assert stats["ok"] is True
    assert stats["processed"] == 0
    assert stats["skipped"] == 1

    remaining = w._list_jobs()
    assert len(remaining) == 1
    assert remaining[0]["cid"] == "cid:demo1"


def test_worker_processes_targeted_job_in_dry_run(tmp_path: Path) -> None:
    w = _mk_worker(tmp_path, operator="op1", dry_run=True)

    res = w.enqueue_job("cid:demo2", targets=["op1"])
    assert res["ok"] is True

    stats = w.run_once()
    assert stats["ok"] is True
    assert stats["processed"] == 1
    assert stats["skipped"] == 0
    assert stats["pinned"] == 0
    assert stats["failed"] == 0

    remaining = w._list_jobs()
    assert len(remaining) == 1
    assert remaining[0]["cid"] == "cid:demo2"
    assert remaining[0]["status"] == "dry_run_seen"


def test_worker_processes_and_deletes_when_not_dry_run(tmp_path: Path) -> None:
    w = _mk_worker(tmp_path, operator="op2", dry_run=False)

    res = w.enqueue_job("cid:demo3", targets=["op2"])
    assert res["ok"] is True

    stats = w.run_once()
    assert stats["ok"] is True
    assert stats["processed"] == 1
    assert stats["pinned"] == 1
    assert stats["failed"] == 0

    remaining = w._list_jobs()
    assert remaining == []


def test_worker_without_targets_is_eligible_for_any_operator(tmp_path: Path) -> None:
    w = _mk_worker(tmp_path, operator="op-free", dry_run=True)

    res = w.enqueue_job("cid:demo4", targets=[])
    assert res["ok"] is True

    stats = w.run_once()
    assert stats["ok"] is True
    assert stats["processed"] == 1
    assert stats["skipped"] == 0

    remaining = w._list_jobs()
    assert len(remaining) == 1
    assert remaining[0]["cid"] == "cid:demo4"
    assert remaining[0]["status"] == "dry_run_seen"
