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
    "tx_submit_total_wall_ms",
    "tx_signature_verify_wall_ms",
    "tx_canonicalize_or_hash_wall_ms",
    "tx_nonce_check_wall_ms",
    "tx_mempool_insert_wall_ms",
    "tx_reject_wall_ms",
    "tx_duplicate_check_wall_ms",
    "block_loop_wall_ms",
    "follower_apply_wall_ms",
    "slow_observer_apply_wall_ms",
    "restart_replay_wall_ms",
    "evidence_write_wall_ms",
]

TX_LOOP_MICROPHASE_FIELDS = [
    "leader_tx_decode_or_normalize_wall_ms",
    "leader_tx_id_or_hash_wall_ms",
    "leader_domain_dispatch_wall_ms",
    "leader_domain_apply_wall_ms",
    "leader_rollback_tracking_wall_ms",
    "follower_tx_decode_or_normalize_wall_ms",
    "follower_tx_id_or_hash_wall_ms",
    "follower_domain_dispatch_wall_ms",
    "follower_domain_apply_wall_ms",
    "follower_rollback_tracking_wall_ms",
    "slow_observer_tx_decode_or_normalize_wall_ms",
    "slow_observer_tx_id_or_hash_wall_ms",
    "slow_observer_domain_dispatch_wall_ms",
    "slow_observer_domain_apply_wall_ms",
    "slow_observer_rollback_tracking_wall_ms",
]

ROLLBACK_JOURNAL_DIAGNOSTIC_FIELDS = [
    "rollback_snapshot_count",
    "rollback_snapshot_bytes_estimate",
    "rollback_snapshot_path_count",
    "rollback_snapshot_duplicate_path_count",
    "rollback_scalar_snapshot_count",
    "rollback_container_snapshot_count",
    "rollback_list_snapshot_count",
    "rollback_dict_snapshot_count",
]

ROLLBACK_JOURNAL_HOTPATH_FIELDS = [
    "rollback_top_snapshot_paths",
    "rollback_top_snapshot_prefixes",
    "rollback_top_snapshot_paths_by_estimated_bytes",
    "rollback_top_dict_snapshot_paths",
    "rollback_top_list_snapshot_paths",
    "rollback_top_duplicate_snapshot_paths",
    "rollback_snapshot_by_tx_kind",
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
    "leader_tx_loop_wall_ms",
    "follower_tx_loop_wall_ms",
    "slow_observer_tx_loop_wall_ms",
    "leader_receipt_build_wall_ms",
    "follower_receipt_build_wall_ms",
    "slow_observer_receipt_build_wall_ms",
    "leader_state_root_wall_ms",
    "follower_state_root_wall_ms",
    "slow_observer_state_root_wall_ms",
    "block_decode_or_materialize_wall_ms",
    "replay_admission_wall_ms",
    "rollback_journal_snapshot_wall_ms",
    *TX_LOOP_MICROPHASE_FIELDS,
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
    assert profile["tx_submit_total_wall_ms"] > 0
    assert profile["tx_mempool_insert_wall_ms"] >= 0
    assert profile["tx_duplicate_check_wall_ms"] >= 0
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
    for field in ROLLBACK_JOURNAL_DIAGNOSTIC_FIELDS:
        assert field in block
        assert isinstance(block[field], int)
        assert block[field] >= 0
    assert block["leader_domain_apply_wall_ms"] >= 0
    assert block["leader_domain_dispatch_wall_ms"] >= 0
    assert block["follower_domain_apply_wall_ms"] >= 0
    assert block["slow_observer_domain_apply_wall_ms"] >= 0
    assert block["rollback_snapshot_count"] >= block["rollback_snapshot_path_count"]
    assert block["rollback_snapshot_duplicate_path_count"] >= 0
    assert block["rollback_list_snapshot_count"] >= 0
    assert block["rollback_dict_snapshot_count"] >= 0
    for field in ROLLBACK_JOURNAL_HOTPATH_FIELDS:
        assert field in block
    assert isinstance(block["rollback_top_snapshot_paths"], list)
    assert isinstance(block["rollback_top_snapshot_prefixes"], list)
    assert isinstance(block["rollback_top_snapshot_paths_by_estimated_bytes"], list)
    assert isinstance(block["rollback_top_dict_snapshot_paths"], list)
    assert isinstance(block["rollback_top_list_snapshot_paths"], list)
    assert isinstance(block["rollback_top_duplicate_snapshot_paths"], list)
    assert isinstance(block["rollback_snapshot_by_tx_kind"], dict)
    assert len(block["rollback_top_snapshot_paths"]) <= 12
    if block["rollback_top_snapshot_paths"]:
        first = block["rollback_top_snapshot_paths"][0]
        assert isinstance(first.get("path"), str)
        assert isinstance(first.get("count"), int)
        assert first["count"] >= 0
    assert "execution_time_ms" in block
    assert "state_root_time_ms" in block
    assert "persistence_time_ms" in block
    assert block["max_txs_per_block_semantics"] == "mempool_candidate_limit_excludes_system_or_derived_txs"
    assert block["requested_mempool_candidate_limit"] == 12
    assert block["selected_candidate_tx_count"] <= block["requested_mempool_candidate_limit"]
    assert block["system_or_derived_txs_included"] >= 0
    assert isinstance(block["tx_count_overage_explained"], bool)
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
        assert "leader_tx_loop_wall_ms" in block
        assert "follower_tx_loop_wall_ms" in block
        assert "slow_observer_tx_loop_wall_ms" in block
        assert block["max_txs_per_block_semantics"] == "mempool_candidate_limit_excludes_system_or_derived_txs"
        assert block["accepted_tx_ids"]
        assert block["receipt_fingerprint"]
        assert profile["convergence"]["all_nodes_converged"] is True, profile["convergence"]
