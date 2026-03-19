from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

from weall.runtime.fault_injection import (
    run_priority2_adversarial_soak,
    run_sqlite_writer_pressure_cross_process_soak,
    run_timeout_epoch_storm_soak,
)


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def test_sqlite_writer_pressure_cross_process_soak_completes_without_counter_loss(tmp_path: Path) -> None:
    summary = run_sqlite_writer_pressure_cross_process_soak(
        work_dir=str(tmp_path / "sqlite-proc"),
        process_count=3,
        writes_per_process=8,
        tx_hold_ms=2,
    )
    assert summary.ok is True
    assert summary.attempts == 24
    assert summary.successes == 24
    assert summary.final_counter == 24
    assert summary.operational_errors == 0
    assert summary.other_errors == 0


def test_timeout_epoch_storm_soak_rejects_duplicates_stales_and_old_epoch(tmp_path: Path) -> None:
    summary = run_timeout_epoch_storm_soak(
        work_dir=str(tmp_path / "timeout-epoch"),
        chain_id="batch26-timeout",
        validator_count=4,
        starting_epoch=3,
        restart_after_view=1,
    )
    assert summary.ok is True
    assert summary.duplicate_timeouts == 3
    assert summary.stale_timeout_rejections >= 6
    assert summary.epoch_replay_attempts == 1
    assert summary.epoch_replay_rejections == 1
    assert summary.restarts == 1
    assert summary.final_view >= 3
    assert summary.highest_tc_view >= 2


def test_priority2_adversarial_soak_cli_reports_all_subsystems_green(tmp_path: Path) -> None:
    env = {"PYTHONPATH": str(_repo_root() / "src")}
    proc = subprocess.run(
        [
            sys.executable,
            str(_repo_root() / "scripts" / "priority2_adversarial_soak.py"),
            "--work-dir",
            str(tmp_path),
            "--chain-id-prefix",
            "batch26-cli",
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
    assert payload["consensus_resilience_matrix"]["ok"] is True
    assert payload["sqlite_writer_pressure"]["ok"] is True
    assert payload["sqlite_writer_pressure_cross_process"]["ok"] is True
    assert payload["timeout_epoch_storm"]["ok"] is True
    assert payload["mempool_spam"]["ok"] is True


def test_priority2_adversarial_soak_direct_runner_is_green(tmp_path: Path) -> None:
    summary = run_priority2_adversarial_soak(
        work_dir=str(tmp_path / "direct"),
        chain_id_prefix="batch26-direct",
    )
    payload = summary.to_json()
    assert payload["ok"] is True
    assert payload["bft"]["rounds_built"] == 18
    assert payload["consensus_resilience_matrix"]["scenarios"]["delayed_qc_after_leader_turnover"]["ok"] is True
    assert payload["consensus_resilience_matrix"]["scenarios"]["epoch_boundary_rejoin_turnover_cycles"]["ok"] is True
    assert payload["sqlite_writer_pressure"]["successes"] == 120
    assert payload["sqlite_writer_pressure_cross_process"]["successes"] == 42
    assert payload["timeout_epoch_storm"]["epoch_replay_rejections"] == 1
