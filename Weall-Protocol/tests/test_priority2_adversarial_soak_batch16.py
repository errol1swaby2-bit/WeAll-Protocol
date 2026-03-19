from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

from weall.runtime.fault_injection import run_bft_fault_injection_soak


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def test_fault_injection_soak_converges_across_partition_restart_and_epoch_bumps(tmp_path: Path) -> None:
    summary = run_bft_fault_injection_soak(
        work_dir=str(tmp_path),
        rounds=12,
        validator_count=4,
        partition_rounds=(3, 4),
        delay_child_first_every=3,
        restart_every=4,
        epoch_bump_rounds=(5, 9),
        stale_qc_replay_target="v2",
        chain_id="bft-batch16",
    )
    assert summary.converged is True
    assert summary.leader_height == 12
    assert summary.partitioned_deliveries >= 2
    assert summary.healed_partition_events >= 2
    assert summary.restart_events >= 3
    assert summary.delayed_child_first_events >= 1
    assert summary.epoch_bump_events == 2
    assert summary.stale_qc_replay_attempts == 2
    assert summary.stale_qc_replay_rejections == 2
    assert all(h == summary.leader_height for h in summary.follower_heights.values())
    assert all(t == summary.leader_tip for t in summary.follower_tips.values())


def test_fault_injection_cli_reports_epoch_bumps_and_stale_qc_rejections(tmp_path: Path) -> None:
    env = {"PYTHONPATH": str(_repo_root() / "src")}
    proc = subprocess.run(
        [
            sys.executable,
            str(_repo_root() / "scripts" / "bft_fault_injection_soak.py"),
            "--work-dir",
            str(tmp_path),
            "--rounds",
            "12",
            "--partition-rounds",
            "3,4",
            "--delay-child-first-every",
            "3",
            "--restart-every",
            "4",
            "--epoch-bump-rounds",
            "5,9",
            "--stale-qc-replay-target",
            "v2",
            "--chain-id",
            "bft-batch16-cli",
        ],
        cwd=str(_repo_root()),
        capture_output=True,
        text=True,
        env=env,
        check=False,
    )
    assert proc.returncode == 0, proc.stderr
    payload = json.loads(proc.stdout)
    assert payload["converged"] is True
    assert int(payload["leader_height"]) == 12
    assert int(payload["epoch_bump_events"]) == 2
    assert int(payload["stale_qc_replay_attempts"]) == 2
    assert int(payload["stale_qc_replay_rejections"]) == 2
