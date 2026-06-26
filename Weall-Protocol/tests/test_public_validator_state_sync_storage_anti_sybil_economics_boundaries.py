from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PROOF = ROOT / "generated" / "b556_b561_final_missing_mechanics_proof_v1_5.json"


def _proof() -> dict:
    return json.loads(PROOF.read_text(encoding="utf-8"))


def test_public_style_validator_network_exercises_mempool_bft_restart() -> None:
    out = _proof()["public_style_validator_network"]
    assert out["ok"] is True
    assert out["node_count"] == 4
    assert out["net_loop_class"] == "weall.net.net_loop.NetMeshLoop"
    assert out["peer_uris_configured_count"] == 12
    assert out["mempool_tx_gossip_model"] == "canonical_peer_envelope_replay"
    assert out["peer_mempool_accept_count"] >= 6
    assert out["follower_apply_all_ok"] is True
    assert all(out["follower_apply_ok_results"])
    assert out["follower_apply_errors"] == ["", "", ""]
    assert out["follower_apply_block_context_fields"] == {"proposer": "v-a", "view": 0}
    assert out["qc_formed"] is True
    assert out["vote_count"] >= out["quorum_threshold"]
    assert out["minority_partition_can_finalize"] is False
    assert out["restart_exercised"] is True
    assert out["state_roots_match_after_restart"] is True
    assert out["public_validator_enabled"] is False


def test_live_peer_state_sync_uses_trusted_anchor_delta_resume_rejections() -> None:
    out = _proof()["live_peer_state_sync"]
    assert out["ok"] is True
    assert out["mode"] == "delta"
    assert out["snapshot_used"] is False
    assert out["fresh_node_started_empty"] is True
    assert out["source_height"] >= 4
    assert out["first_sync_block_count"] == 2
    assert out["resume_sync_block_count"] >= 1
    assert out["state_roots_match"] is True
    assert out["corrupt_peer_data_rejected"] is True
    assert out["wrong_chain_rejected"] is True


def test_multi_operator_storage_workers_reassign_and_confirm_retrieval() -> None:
    out = _proof()["multi_operator_storage_workers"]
    assert out["ok"] is True
    assert out["worker_model"] == "multi_operator_local_file_pin_workers"
    assert out["operator_count"] >= 4
    assert out["failed_operator"] not in {"", out["replacement_operator"]}
    assert out["retrieval_confirmed"] is True
    assert out["availability_status"] == "available"
    assert out["retrieval_proof_count"] >= 1
    assert out["public_decentralized_media_claimed"] is False


def test_anti_sybil_records_collusion_suspicion_without_overclaiming() -> None:
    out = _proof()["anti_sybil_collusion_accountability"]
    assert out["ok"] is True
    assert out["reviewer_count_flagged"] >= 2
    assert out["reviewer_collusion_suspicion_recorded"] is True
    suspicion = out["reviewer_collusion_suspicion"]
    assert suspicion["requires_followup_review"] is True
    assert suspicion["status"] == "suspected_prior_approval_cluster"
    assert out["evidence_retention_after_recovery"]["deletion_eligible"] is True
    assert out["duplicate_human_detection_claimed"] is False
    assert out["collusion_adjudication_claimed"] is False


def test_economics_activation_complete_but_locked() -> None:
    out = _proof()["economics_activation_locked_completion"]
    assert out["ok"] is True
    assert out["strict_preconditions_missing_error"] == "economics_activation_preconditions_not_satisfied"
    assert out["preconditions_ready_if_governance_chooses_activation"] is True
    assert out["wallet_initialization_policy_present"] is True
    assert out["reward_recipient_eligibility_present"] is True
    assert out["anti_farming_policy_present"] is True
    assert out["transfer_receipt_policy_present"] is True
    assert out["treasury_accountability_policy_present"] is True
    assert out["live_economics_enabled"] is False
    assert out["transfer_before_activation_rejected_reason"] == "economics_disabled"


def test_helper_serial_equivalence_expands_without_activation() -> None:
    out = _proof()["helper_serial_equivalence_expansion"]
    assert out["ok"] is True
    assert out["tx_count"] >= 10
    assert out["serial_equivalence_ok"] is True
    assert out["missing_helper_fallback_reasons"]
    assert out["byzantine_helper_rejection_reasons"]
    assert out["missing_helper_preserves_tx_order"] is True
    assert out["byzantine_helper_preserves_tx_order"] is True
    assert out["production_helper_execution_enabled"] is False


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
        [sys.executable, "scripts/gen_b556_b561_final_missing_mechanics_proof_v1_5.py", "--check"],
        cwd=str(ROOT),
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
