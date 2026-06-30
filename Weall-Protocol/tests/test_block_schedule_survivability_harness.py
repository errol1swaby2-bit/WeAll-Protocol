from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


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
    result = subprocess.run(cmd, cwd=root, text=True, capture_output=True, timeout=60, check=False)
    assert result.returncode == 0, result.stderr + result.stdout
    evidence = json.loads(out.read_text())
    profile = evidence["profiles"][0]
    assert profile["profile"] == "light"
    assert profile["block_measurements"], evidence
    block = profile["block_measurements"][0]
    assert block["ok"] is True, block
    assert block["txs_included"] > 0, block
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
    result = subprocess.run(cmd, cwd=root, text=True, capture_output=True, timeout=90, check=False)
    assert result.returncode == 0, result.stderr + result.stdout
    evidence = json.loads(out.read_text())
    assert evidence["execution_models"] == ["deepcopy", "bounded_rollback"]
    profiles = evidence["profiles"]
    assert [p["execution_model"] for p in profiles] == ["deepcopy", "bounded_rollback"]
    for profile in profiles:
        block = profile["block_measurements"][0]
        assert block["ok"] is True, block
        assert block["execution_model"] == profile["execution_model"]
        assert "execution_time_ms" in block
        assert profile["convergence"]["all_nodes_converged"] is True, profile["convergence"]
