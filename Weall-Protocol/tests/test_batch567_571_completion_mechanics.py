from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PROOF = ROOT / "generated" / "b567_b571_autonomous_mechanics_proof_v1_5.json"


def _proof() -> dict:
    return json.loads(PROOF.read_text(encoding="utf-8"))


def test_batch567_autonomous_validator_gossip_loop_handles_partition_rejoin_churn() -> None:
    out = _proof()["autonomous_validator_gossip_loop"]
    assert out["ok"] is True
    assert out["node_count"] == 4
    assert out["autonomous_loop_model"] == "threaded_validator_gossip_loops"
    assert out["mempool_gossip_autonomous"] is True
    assert out["proposal_gossip_autonomous"] is True
    assert out["vote_qc_gossip_autonomous"] is True
    assert out["network_delay_reordering_exercised"] is True
    assert set(out["mempool_counts_after_gossip"].values()) == {3}
    assert out["majority_qc_formed"] is True
    assert out["minority_partition_can_finalize"] is False
    assert out["partition_rejoin_exercised"] is True
    assert out["validator_churn_restart_exercised"] is True
    assert out["fresh_catchup_from_live_peer_log"] is True
    assert set(out["heights_final"].values()) == {2}
    assert out["state_roots_match"] is True
    assert out["public_validator_readiness_claimed"] is False


def test_batch568_fresh_node_catches_up_from_autonomous_live_peer_log() -> None:
    out = _proof()["fresh_node_catchup_autonomous_network"]
    assert out["ok"] is True
    assert out["source_network_model"] == "threaded_validator_gossip_loops"
    assert out["fresh_node_started_empty"] is True
    assert out["trusted_anchor_source"] == "live_validator_peer_finalized_tip"
    assert out["trusted_anchor_height"] == 2
    assert out["applied_results"] == [True, True]
    assert out["interrupted_height"] == 1
    assert out["state_roots_match"] is True
    assert out["wrong_chain_rejected"] is True
    assert out["corrupt_peer_data_rejected"] is True
    assert out["snapshot_used"] is False
    assert out["public_peer_network_claimed"] is False


def test_batch569_multiprocess_ipfs_operator_durability_reassigns_after_process_failure() -> None:
    out = _proof()["multiprocess_ipfs_operator_durability"]
    assert out["ok"] is True
    assert out["worker_model"] == "multiprocess_ipfs_compatible_operator_workers"
    assert out["operator_count"] == 4
    assert out["failed_operator"] != out["replacement_operator"]
    assert out["failed_process_exitcode"] is not None
    assert out["reassignment_recorded"] is True
    assert out["replacement_add_result"]["ok"] is True
    assert out["replacement_cat_result"]["ok"] is True
    assert out["retrieval_confirmed"] is True
    assert out["availability_status"] == "available"
    assert out["retrieval_proof_count"] >= 1
    assert out["public_decentralized_media_claimed"] is False


def test_batch570_anti_sybil_adjudication_and_evidence_deletion_execute() -> None:
    out = _proof()["anti_sybil_adjudication_deletion"]
    assert out["ok"] is True
    assert out["confirmed_adjudication"]["status"] == "adjudicated_confirmed"
    assert out["dismissed_adjudication"]["status"] == "adjudicated_dismissed"
    assert all(not rec["eligible"] for rec in out["scores_after_confirm"].values())
    assert all(rec["eligible"] for rec in out["scores_after_dismiss"].values())
    assert out["evidence_deletion"]["deleted"] is True
    assert out["final_retention_record"]["deleted"] is True
    assert out["final_retention_record"]["raw_evidence_retained"] is False
    assert len(out["evidence_deletion"]["minimal_audit_hash"]) == 64
    assert out["duplicate_human_detection_claimed"] is False
    assert out["automatic_collusion_detection_claimed"] is False


def test_batch571_economics_locked_read_models_surface_pending_failed_reward_treasury() -> None:
    out = _proof()["economics_locked_read_models"]
    assert out["ok"] is True
    assert out["economics_enabled"] is False
    assert out["live_mutation_enabled"] is False
    assert out["transfer_before_activation_rejected_reason"] == "economics_disabled"
    assert out["pending_transfer_record"]["status"] == "pending"
    assert out["failed_transfer_record"]["status"] == "failed"
    assert out["reward_claim_ledger_claim_count"] == 2
    assert out["reward_claim_ledger_epoch_12"] == ["reward-1", "reward-2"]
    assert out["treasury_report"]["public_accountability_report"] is True
    assert out["treasury_report_count"] == 1
    assert out["legal_compliance_review_boundary"] == "required_before_activation"
    assert out["live_economics_claimed"] is False


def test_batch567_571_claim_boundaries_and_artifact_freshness() -> None:
    proof = _proof()
    assert proof["ok"] is True
    assert proof["private_testnet_candidate_strengthened"] is True
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
        [sys.executable, "scripts/gen_b567_b571_autonomous_mechanics_proof_v1_5.py", "--check"],
        cwd=str(ROOT),
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
