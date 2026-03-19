from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

from weall.runtime.fault_injection import (
    run_mempool_spam_stress,
    run_priority1_heavy_soak,
    run_sqlite_writer_pressure_soak,
)


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def test_sqlite_writer_pressure_soak_completes_without_counter_loss(tmp_path: Path) -> None:
    summary = run_sqlite_writer_pressure_soak(
        work_dir=str(tmp_path / "sqlite"),
        worker_count=4,
        writes_per_worker=12,
        tx_hold_ms=2,
        checkpoint_interval_ms=10,
    )
    assert summary.ok is True
    assert summary.attempts == 48
    assert summary.successes == 48
    assert summary.final_counter == 48
    assert summary.operational_errors == 0
    assert summary.other_errors == 0
    assert summary.maintenance_ticks >= 1


def test_mempool_spam_stress_drains_unique_transactions_after_duplicate_burst(tmp_path: Path) -> None:
    summary = run_mempool_spam_stress(
        work_dir=str(tmp_path / "mempool"),
        chain_id="batch19-mempool",
        worker_count=4,
        txs_per_worker=18,
        duplicate_every=6,
        block_batch_size=15,
    )
    assert summary.ok is True
    assert summary.attempts == 84
    assert summary.accepted == 72
    assert summary.unique_tx_ids == 72
    assert summary.duplicate_accepts == 0
    assert summary.rejected == 12
    assert summary.committed_tx_count == 72
    assert summary.final_mempool_size == 0
    assert summary.blocks_produced >= 5


def test_priority1_heavy_soak_cli_reports_all_subsystems_green(tmp_path: Path) -> None:
    env = {"PYTHONPATH": str(_repo_root() / "src")}
    proc = subprocess.run(
        [
            sys.executable,
            str(_repo_root() / "scripts" / "priority1_heavy_soak.py"),
            "--work-dir",
            str(tmp_path),
            "--chain-id-prefix",
            "batch19-heavy",
        ],
        cwd=str(_repo_root()),
        capture_output=True,
        text=True,
        env=env,
        check=False,
    )
    assert proc.returncode == 0, proc.stderr
    payload = json.loads(proc.stdout)
    assert payload["ok"] is True
    assert payload["bft"]["converged"] is True
    assert payload["sqlite_writer_pressure"]["ok"] is True
    assert payload["sqlite_writer_pressure"]["final_counter"] == payload["sqlite_writer_pressure"]["successes"]
    assert payload["mempool_spam"]["ok"] is True
    assert payload["mempool_spam"]["final_mempool_size"] == 0
    assert payload["mempool_spam"]["committed_tx_count"] == payload["mempool_spam"]["unique_tx_ids"]


def test_priority1_heavy_soak_direct_runner_is_green(tmp_path: Path) -> None:
    summary = run_priority1_heavy_soak(
        work_dir=str(tmp_path / "heavy"),
        chain_id_prefix="batch19-direct",
    )
    payload = summary.to_json()
    assert payload["ok"] is True
    assert payload["bft"]["rounds_built"] == 15
    assert payload["sqlite_writer_pressure"]["successes"] == 80
    assert payload["mempool_spam"]["unique_tx_ids"] == 96
