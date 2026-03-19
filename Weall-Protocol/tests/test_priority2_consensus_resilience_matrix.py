from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

from weall.runtime.fault_injection import run_consensus_resilience_matrix


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def test_consensus_resilience_matrix_direct_runner_is_green(tmp_path: Path) -> None:
    summary = run_consensus_resilience_matrix(
        work_dir=str(tmp_path / "matrix"),
        chain_id_prefix="batch31-consensus-resilience",
    )
    payload = summary.to_json()
    assert payload["ok"] is True

    restart = payload["scenarios"]["proposal_replay_after_restart"]
    assert restart["ok"] is True
    assert int(restart["restart_events"]) == 1
    assert restart["initial_vote"] is True
    assert restart["replayed_vote"] is True

    conflict = payload["scenarios"]["conflicting_nonleader_proposal_rejected"]
    assert conflict["ok"] is True
    assert conflict["valid_promoted"] is True
    assert conflict["forged_rejected"] is True

    turnover = payload["scenarios"]["delayed_qc_after_leader_turnover"]
    assert turnover["ok"] is True
    assert turnover["initial_vote"] is True
    assert turnover["delayed_qc_applied"] is True
    assert turnover["second_leader_vote"] is True
    assert turnover["high_qc_block_id"] != ""

    convergence = payload["scenarios"]["partition_heal_restart_under_load"]
    assert convergence["ok"] is True
    assert convergence["converged"] is True
    assert int(convergence["restart_events"]) >= 3
    assert int(convergence["healed_partition_events"]) >= 4

    epoch_boundary = payload["scenarios"]["epoch_boundary_rejoin_turnover_cycles"]
    assert epoch_boundary["ok"] is True
    assert epoch_boundary["converged"] is True
    assert int(epoch_boundary["epoch_bump_events"]) == 3
    assert int(epoch_boundary["restart_events"]) >= 10
    assert int(epoch_boundary["stale_qc_replay_rejections"]) == int(epoch_boundary["stale_qc_replay_attempts"])
    assert int(epoch_boundary["healed_partition_events"]) >= 6


def test_consensus_resilience_matrix_cli_reports_all_scenarios_green(tmp_path: Path) -> None:
    env = {"PYTHONPATH": str(_repo_root() / "src")}
    proc = subprocess.run(
        [
            sys.executable,
            str(_repo_root() / "scripts" / "bft_consensus_resilience_matrix.py"),
            "--work-dir",
            str(tmp_path),
            "--chain-id-prefix",
            "batch31-consensus-cli",
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
    assert sorted(payload["scenarios"].keys()) == [
        "conflicting_nonleader_proposal_rejected",
        "delayed_qc_after_leader_turnover",
        "epoch_boundary_rejoin_turnover_cycles",
        "partition_heal_restart_under_load",
        "proposal_replay_after_restart",
    ]
