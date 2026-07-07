from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PROOF = ROOT / "generated" / "b562_b566_mechanics_hardening_proof_v1_5.json"


def _proof() -> dict:
    return json.loads(PROOF.read_text(encoding="utf-8"))


def test_validator_follower_apply_is_enforced() -> None:
    out = _proof()["validator_follower_apply_hardening"]
    assert out["ok"] is True
    assert out["follower_apply_all_ok"] is True
    assert out["follower_apply_ok_results"] == [True, True, True]
    assert out["follower_apply_errors"] == ["", "", ""]
    assert out["block_context_fields"] == {"proposer": "v-a", "view": 0}
    assert out["state_roots_match_after_restart"] is True
    assert out["public_validator_enabled"] is False
    assert out["public_validator_readiness_claimed"] is False


def test_fresh_node_catches_up_from_actual_follower_state() -> None:
    out = _proof()["live_peer_catchup_from_follower_state"]
    assert out["ok"] is True
    assert out["source_peer"] == "follower-validator-state"
    assert out["follower_height"] >= 3
    assert out["fresh_node_started_empty"] is True
    assert out["interrupted_height"] >= 1
    assert out["first_sync_block_count"] >= 1
    assert out["resume_sync_block_count"] >= 1
    assert out["state_roots_match"] is True
    assert out["snapshot_used"] is False


def test_storage_worker_retry_loop_reassigns_after_exhaustion() -> None:
    out = _proof()["storage_worker_failure_retry_loop"]
    assert out["ok"] is True
    assert out["worker_model"] == "multi_operator_local_file_pin_workers_with_retry_loop"
    assert out["operator_count"] >= 4
    assert out["failed_operator_retry_attempts"] == 2
    assert out["failed_operator_retry_results"] == [False, False]
    assert out["failed_operator"] != out["replacement_operator"]
    assert out["reassignment_recorded"] is True
    assert any(out["replacement_attempt_results"])
    assert out["retrieval_confirmed"] is True
    assert out["availability_status"] == "available"
    assert out["retrieval_proof_count"] >= 1
    assert out["public_decentralized_media_claimed"] is False


def test_anti_sybil_escalation_and_recovery_windows() -> None:
    out = _proof()["anti_sybil_escalation_recovery_windows"]
    assert out["ok"] is True
    assert out["escalation_level"] == "review_required"
    assert out["review_window_close_height"] > out["review_window_open_height"]
    assert out["recovery_eligible_after_height"] == out["review_window_close_height"]
    assert out["recovery_policy"] == "eligible_after_followup_review_or_successful_reverification"
    assert out["retention_before_recovery"]["deletion_eligible"] is False
    assert out["retention_after_recovery"]["deletion_eligible"] is True
    assert out["duplicate_human_detection_claimed"] is False
    assert out["collusion_adjudication_claimed"] is False


def test_economics_farming_simulation_remains_locked() -> None:
    out = _proof()["economics_farming_simulation_locked"]
    assert out["ok"] is True
    assert out["activation_preconditions_ready"] is True
    assert out["live_economics_enabled"] is False
    assert out["transfer_before_activation_rejected_reason"] == "economics_disabled"
    assert out["first_unique_claim"]["ok"] is True
    assert out["duplicate_work_rejection"]["reason"] == "duplicate_work_id_epoch"
    assert out["max_claims_rejection"]["reason"] == "max_reward_claims_per_epoch_exceeded"
    assert out["inactive_poh_rejection"]["reason"] == "recipient_requires_active_poh"
    assert out["locked_account_rejection"]["reason"] == "recipient_locked_or_banned"
    assert out["long_run_simulation_claimed"] is False
    assert out["legal_compliance_claimed"] is False


def test_claim_boundaries_and_artifact_freshness() -> None:
    proof = _proof()
    assert proof["ok"] is True
    assert proof["controlled_testnet_candidate_strengthened"] is True
    assert proof["public_beta_ready"] is False
    assert proof["claim_boundaries"] == {
        "automatic_protocol_upgrades": False,
        "complete_anti_sybil_solved": False,
        "live_economics": False,
        "mainnet_readiness": False,
        "personalized_feed_ranking": False,
        "production_helper_execution": False,
        "public_multi_validator_bft": False,
        "public_validator_readiness": False,
    }
    proc = subprocess.run(
        [sys.executable, "scripts/gen_b562_b566_mechanics_hardening_proof_v1_5.py", "--check"],
        cwd=str(ROOT),
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
