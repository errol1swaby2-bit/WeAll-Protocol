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

REPLAY_WRAPPER_PHASES = [
    "runtime_context_wall_ms",
    "block_hash_validation_wall_ms",
    "replay_admission_wall_ms",
    "state_deepcopy_wall_ms",
    "clock_policy_wall_ms",
    "pre_scheduler_wall_ms",
    "pre_system_emitter_wall_ms",
    "post_scheduler_wall_ms",
    "post_system_emitter_wall_ms",
    "post_system_emitter_scan_wall_ms",
    "post_system_emitter_materialize_wall_ms",
    "post_system_emitter_validate_wall_ms",
    "post_system_emitter_enqueue_wall_ms",
    "post_system_emitter_receipt_link_wall_ms",
    "post_system_emitter_state_write_wall_ms",
    "system_queue_binding_wall_ms",
    "system_queue_binding_scan_wall_ms",
    "system_queue_binding_materialize_wall_ms",
    "system_queue_binding_validate_wall_ms",
    "system_queue_binding_dedupe_wall_ms",
    "system_queue_binding_sort_wall_ms",
    "system_queue_binding_state_write_wall_ms",
    "system_queue_prune_wall_ms",
    "receipts_root_wall_ms",
    "recent_anchor_wall_ms",
    "vrf_validation_wall_ms",
    "helper_validation_wall_ms",
    "metadata_update_wall_ms",
    "commit_persistence_wall_ms",
    "commit_block_json_wall_ms",
    "commit_state_json_wall_ms",
    "commit_prune_wall_ms",
    "replay_unattributed_wall_ms",
]

REPLAY_WRAPPER_COUNT_FIELDS = [
    "system_queue_items_seen",
    "system_queue_items_bound",
    "post_system_emitter_items_seen",
    "post_system_emitter_items_emitted",
    "post_system_emitter_items_skipped",
    "system_queue_duplicate_items",
    "system_queue_noop_items",
]

REPLAY_WRAPPER_TIMING_FIELDS = [
    f"{prefix}_{field}"
    for prefix in ("follower", "slow_observer")
    for field in REPLAY_WRAPPER_PHASES
]

REPLAY_WRAPPER_COUNTER_FIELDS = [
    f"{prefix}_{field}"
    for prefix in ("follower", "slow_observer")
    for field in REPLAY_WRAPPER_COUNT_FIELDS
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
    *REPLAY_WRAPPER_TIMING_FIELDS,
    *REPLAY_WRAPPER_COUNTER_FIELDS,
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
    assert profile["sustain_load"] is False
    assert profile["txs_per_block_feed_semantics"] == "per_block_initial_submit_count_not_candidate_guarantee"
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
    assert block["follower_commit_persistence_wall_ms"] >= 0
    assert block["slow_observer_commit_persistence_wall_ms"] >= 0
    assert block["follower_replay_unattributed_wall_ms"] >= 0
    assert block["slow_observer_replay_unattributed_wall_ms"] >= 0
    for field in REPLAY_WRAPPER_COUNTER_FIELDS:
        assert field in block
        assert isinstance(block[field], int)
        assert block[field] >= 0
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
    for field in [
        "initial_pre_refill_mempool_size",
        "pre_block_mempool_size",
        "post_block_mempool_size",
        "valid_candidate_count",
        "admitted_before_block_count",
        "rejected_before_block_count",
        "per_block_refill_submitted",
        "per_block_refill_admitted",
        "per_block_refill_rejected",
        "per_block_refill_attempts",
    ]:
        assert field in block
        assert isinstance(block[field], int)
        assert block[field] >= 0
    assert block["sustain_load"] is False
    assert block["per_block_refill_submitted"] == 0
    assert block["per_block_refill_attempts"] == 0
    assert block["per_block_target_met"] == (block["valid_candidate_count"] >= block["requested_mempool_candidate_limit"])
    assert profile["convergence"]["all_nodes_converged"] is True, profile["convergence"]


def test_sustain_load_mode_refills_and_reports_per_block_targets(tmp_path: Path) -> None:
    root = _repo_root()
    out = tmp_path / "sustain-evidence.json"
    cmd = [
        sys.executable,
        str(root / "scripts" / "rehearse_block_schedule_survivability_v1_5.py"),
        "--profile",
        "light",
        "--users",
        "10",
        "--blocks",
        "2",
        "--max-txs-per-block",
        "18",
        "--txs-per-block-feed",
        "6",
        "--sustain-load",
        "--out",
        str(out),
    ]
    result = subprocess.run(cmd, cwd=root, env=_subprocess_env(), text=True, capture_output=True, timeout=90, check=False)
    assert result.returncode == 0, result.stderr + result.stdout
    evidence = json.loads(out.read_text())
    profile = evidence["profiles"][0]
    assert profile["sustain_load"] is True
    assert profile["txs_per_block_feed_semantics"] == "per_block_initial_submit_count_with_deterministic_candidate_top_up"
    assert len(profile["block_measurements"]) == 2
    for block in profile["block_measurements"]:
        assert block["sustain_load"] is True
        for field in [
            "initial_pre_refill_mempool_size",
            "pre_block_mempool_size",
            "post_block_mempool_size",
            "valid_candidate_count",
            "admitted_before_block_count",
            "rejected_before_block_count",
            "per_block_refill_submitted",
            "per_block_refill_admitted",
            "per_block_refill_rejected",
            "per_block_refill_attempts",
        ]:
            assert field in block
            assert isinstance(block[field], int)
            assert block[field] >= 0
        assert block["per_block_refill_submitted"] >= 0
        assert block["per_block_refill_admitted"] + block["per_block_refill_rejected"] <= block["per_block_refill_submitted"]
        assert block["per_block_target_met"] == (block["valid_candidate_count"] >= block["requested_mempool_candidate_limit"])
        if block["per_block_target_met"]:
            assert block["selected_candidate_tx_count"] >= min(block["requested_mempool_candidate_limit"], block["valid_candidate_count"])
    assert profile["aggregate_submit"]["admitted"] >= sum(
        int(block["admitted_before_block_count"]) for block in profile["block_measurements"]
    )
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
