from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path



def _subprocess_env() -> dict[str, str]:
    env = os.environ.copy()
    env.update(
        {
            "WEALL_API_BOOT_RUNTIME": "0",
            "WEALL_MODE": "dev",
            "WEALL_UNSAFE_DEV": "1",
            "WEALL_SQLITE_ALLOW_NON_WAL": "1",
            "WEALL_DISABLE_BLOCK_PRODUCER": "1",
        }
    )
    return env

def _repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


PROFILE_TIMING_FIELDS = [
    "profile_total_wall_ms",
    "setup_wall_ms",
    "user_prepare_wall_ms",
    "tx_generation_wall_ms",
    "mempool_submit_wall_ms",
    "block_loop_wall_ms",
    "follower_apply_wall_ms",
    "slow_observer_apply_wall_ms",
    "restart_replay_wall_ms",
    "evidence_write_wall_ms",
]

BLOCK_TIMING_FIELDS = [
    "block_total_wall_ms",
    "candidate_selection_wall_ms",
    "leader_block_build_wall_ms",
    "leader_apply_or_execute_wall_ms",
    "follower_apply_wall_ms",
    "slow_observer_apply_wall_ms",
    "state_root_wall_ms",
    "receipt_or_summary_wall_ms",
]


def _assert_non_negative_number(value: object) -> None:
    assert isinstance(value, (int, float)), value
    assert value >= 0, value


def test_block_schedule_budget_totals_target_interval() -> None:
    root = _repo_root()
    budget = json.loads((root / "specs" / "block_schedule_survivability_budget_v1_5.json").read_text())
    assert budget["target_block_interval_ms"] == 20_000
    assert sum(int(v) for v in budget["phase_budget_ms"].values()) == 20_000
    assert budget["phase_budget_ms"]["transaction_execution"] > budget["phase_budget_ms"]["mempool_selection"]
    assert budget["public_testnet_initial_recommended_limits"]["max_txs_per_block_until_measured_active_profile_passes"] <= 250


def test_light_block_schedule_rehearsal_generates_machine_readable_evidence(tmp_path: Path) -> None:
    root = _repo_root()
    out = tmp_path / "light-evidence.json"
    cmd = [
        sys.executable,
        str(root / "scripts" / "rehearse_block_schedule_survivability_v1_5.py"),
        "--profile",
        "light",
        "--users",
        "6",
        "--blocks",
        "1",
        "--max-txs-per-block",
        "12",
        "--txs-per-block-feed",
        "14",
        "--out",
        str(out),
    ]
    result = subprocess.run(cmd, cwd=root, env=_subprocess_env(), text=True, capture_output=True, timeout=60, check=False)
    assert result.returncode == 0, result.stderr + result.stdout
    evidence = json.loads(out.read_text())
    assert evidence["execution_models"] == ["bounded_rollback"]
    assert "bottleneck_summary" in evidence
    assert len(evidence["bottleneck_summary"]["top_5"]) <= 5
    _assert_non_negative_number(evidence["evidence_write_wall_ms"])
    profile = evidence["profiles"][0]
    assert profile["profile"] == "light"
    for field in PROFILE_TIMING_FIELDS:
        assert field in profile
        _assert_non_negative_number(profile[field])
    assert "profile_bottleneck_summary" in profile
    assert len(profile["profile_bottleneck_summary"]["top_5"]) <= 5
    assert profile["block_measurements"], evidence
    block = profile["block_measurements"][0]
    assert block["ok"] is True, block
    assert block["txs_included"] > 0, block
    assert "total_block_production_time_ms" in block
    for field in BLOCK_TIMING_FIELDS:
        assert field in block
        _assert_non_negative_number(block[field])
    assert "execution_time_ms" in block
    assert "state_root_time_ms" in block
    assert "persistence_time_ms" in block
    assert profile["convergence"]["all_nodes_converged"] is True, profile["convergence"]


def test_block_schedule_rehearsal_can_compare_deepcopy_and_bounded_rollback(tmp_path: Path) -> None:
    root = _repo_root()
    out = tmp_path / "compare-evidence.json"
    cmd = [
        sys.executable,
        str(root / "scripts" / "rehearse_block_schedule_survivability_v1_5.py"),
        "--profile",
        "light",
        "--users",
        "6",
        "--blocks",
        "1",
        "--max-txs-per-block",
        "12",
        "--txs-per-block-feed",
        "14",
        "--execution-model",
        "compare",
        "--out",
        str(out),
    ]
    result = subprocess.run(cmd, cwd=root, env=_subprocess_env(), text=True, capture_output=True, timeout=90, check=False)
    assert result.returncode == 0, result.stderr + result.stdout
    evidence = json.loads(out.read_text())
    assert evidence["execution_models"] == ["deepcopy", "bounded_rollback"]
    assert evidence["compare_equivalence"]["ok"] is True
    assert evidence["compare_equivalence"]["profiles"]["light"]["ok"] is True
    assert "bottleneck_summary" in evidence
    assert len(evidence["bottleneck_summary"]["top_5"]) <= 5
    profiles = evidence["profiles"]
    assert [p["execution_model"] for p in profiles] == ["deepcopy", "bounded_rollback"]
    assert len({p["chain_id"] for p in profiles}) == 1
    for profile in profiles:
        for field in PROFILE_TIMING_FIELDS:
            assert field in profile
            _assert_non_negative_number(profile[field])
        assert "profile_bottleneck_summary" in profile
        block = profile["block_measurements"][0]
        assert block["ok"] is True, block
        assert block["execution_model"] == profile["execution_model"]
        for field in BLOCK_TIMING_FIELDS:
            assert field in block
            _assert_non_negative_number(block[field])
        assert "execution_time_ms" in block
        assert block["accepted_tx_ids"]
        assert block["receipt_fingerprint"]
        assert profile["convergence"]["all_nodes_converged"] is True, profile["convergence"]
