from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

from weall.runtime.fault_injection import run_bft_fault_injection_soak


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def test_fault_injection_soak_converges_after_partition_restart_and_child_first(tmp_path: Path) -> None:
    summary = run_bft_fault_injection_soak(
        work_dir=str(tmp_path),
        rounds=10,
        validator_count=4,
        partition_rounds=(3, 4),
        delay_child_first_every=3,
        restart_every=4,
        chain_id="bft-batch7",
    )
    assert summary.converged is True
    assert summary.leader_height == 10
    assert summary.partitioned_deliveries >= 2
    assert summary.healed_partition_events >= 2
    assert summary.restart_events >= 2
    assert summary.delayed_child_first_events >= 1
    assert all(h == summary.leader_height for h in summary.follower_heights.values())
    assert all(t == summary.leader_tip for t in summary.follower_tips.values())
    assert all(not list((diag.get("pending_fetch_requests") or [])) for diag in summary.follower_diagnostics.values())


def test_fault_injection_cli_emits_summary_json(tmp_path: Path) -> None:
    env = dict()
    env.update(PYTHONPATH=str(_repo_root() / "src"))
    proc = subprocess.run(
        [
            sys.executable,
            str(_repo_root() / "scripts" / "bft_fault_injection_soak.py"),
            "--work-dir",
            str(tmp_path),
            "--rounds",
            "8",
            "--partition-rounds",
            "2,3",
            "--delay-child-first-every",
            "3",
            "--restart-every",
            "4",
            "--chain-id",
            "bft-batch7-cli",
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
    assert int(payload["leader_height"]) == 8
    assert int(payload["restart_events"]) >= 2
