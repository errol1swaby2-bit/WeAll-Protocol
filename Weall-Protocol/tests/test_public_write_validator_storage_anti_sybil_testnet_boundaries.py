from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PROOF = ROOT / "generated" / "b549_b553_controlled_testnet_candidate_proof_v1_5.json"


def _proof() -> dict:
    return json.loads(PROOF.read_text(encoding="utf-8"))


def test_batch549_poh_challenge_public_write_path_closes_gap() -> None:
    out = _proof()["poh_challenge_public_write"]
    assert out["ok"] is True
    assert out["skeleton_route"] == "POST /v1/poh/challenge/tx/open"
    assert out["submit_route"] == "POST /v1/tx/submit POH_CHALLENGE_OPEN"
    assert out["challenge_status"] == "open"
    assert out["challenge_case_id"] == "case-a"
    assert out["public_client_write_gap_closed"] is True
    assert out["system_or_receipt_submission_required"] is False


def test_batch550_long_lived_validator_network_skeleton_uses_four_netloops() -> None:
    out = _proof()["long_lived_validator_network_skeleton"]
    assert out["ok"] is True
    assert out["node_count"] == 4
    assert out["net_loop_class"] == "weall.net.net_loop.NetMeshLoop"
    assert out["ports_bound_count"] == 4
    assert out["produced_height"] >= 2
    assert out["restart_exercised"] is True
    assert out["restart_root_matches"] is True
    assert out["public_validator_enabled"] is False
    assert out["public_beta_ready"] is False


def test_batch551_multi_operator_storage_durability_keeps_public_media_boundary() -> None:
    out = _proof()["multi_operator_storage_durability"]
    assert out["ok"] is True
    assert out["multi_operator_count"] >= 3
    assert out["reassignment_recorded"] is True
    assert out["retrieval_confirmed"] is True
    assert out["availability_status"] == "available"
    assert out["public_decentralized_media_claimed"] is False


def test_batch552_anti_sybil_evidence_retention_and_recovery_policy() -> None:
    out = _proof()["anti_sybil_evidence_retention_recovery"]
    assert out["ok"] is True
    assert out["retention_before_reverification"]["status"] == "retain_until_reverification_or_appeal"
    assert out["retention_before_reverification"]["appeal_remedy_available"] is True
    assert out["retention_after_reverification"]["status"] == "remedy_completed_minimal_retention"
    assert out["retention_after_reverification"]["deletion_eligible"] is True
    assert out["reverification_status"] == "completed"
    assert out["reviewer_accountability_recorded"] is True
    assert out["duplicate_human_detection_claimed"] is False
    assert out["collusion_detection_claimed"] is False


def test_batch553_controlled_testnet_candidate_bundle_preserves_claim_boundaries() -> None:
    proof = _proof()
    assert proof["ok"] is True
    candidate = proof["controlled_testnet_candidate_evidence"]
    assert candidate["controlled_testnet_rehearsal_candidate"] is True
    assert candidate["public_beta_ready"] is False
    assert candidate["poh_challenge_public_client_gap_closed"] is True
    assert candidate["validator_rehearsal_node_count"] == 4
    assert candidate["storage_operator_count"] >= 3
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
    assert proof["remaining_public_testnet_gaps"]


def test_batch549_553_generated_artifact_is_fresh() -> None:
    proc = subprocess.run(
        [sys.executable, "scripts/gen_b549_b553_controlled_testnet_candidate_proof_v1_5.py", "--check"],
        cwd=str(ROOT),
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
