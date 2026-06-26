from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PROOF = ROOT / "generated" / "b582_b586_readiness_truth_and_proof_v1_5.json"


def _proof() -> dict:
    return json.loads(PROOF.read_text(encoding="utf-8"))


def test_gap_register_truth_reflects_initial_artifacts_without_overclaiming() -> None:
    proof = _proof()["gap_register_truth_refresh"]
    assert proof["ok"] is True
    assert proof["state_root_vector_gap_status"] == "initial_vector_pack_added_needs_cross_machine_release_vectors"
    assert proof["economic_simulation_gap_status"] == "initial_simulation_added_activation_still_blocked"
    assert proof["public_beta_ready_claimed"] is False
    assert proof["live_economics_claimed"] is False
    assert proof["public_validator_readiness_claimed"] is False

    gap = json.loads((ROOT / "generated" / "v15_implementation_gap_register.json").read_text(encoding="utf-8"))
    entries = {item["id"]: item for item in gap["remaining_p0_p1_gaps"]}
    assert "generated/state_root_vectors_v1_5.json" in entries["P1-STATE-ROOT-VECTORS"]["evidence"]
    assert "generated/tokenomics_simulation_v1_5.json" in entries["P1-ECONOMIC-SIMULATION-PACK"]["evidence"]
    assert "public beta" in entries["P1-STATE-ROOT-VECTORS"]["next_gate"].lower()
    assert "before any activation" in entries["P1-ECONOMIC-SIMULATION-PACK"]["next_gate"].lower()


def test_poh_operator_routes_have_explicit_env_token_metadata() -> None:
    proof = _proof()["poh_operator_route_metadata"]
    assert proof["ok"] is True
    assert proof["operator_routes_explicit_metadata"] is True
    assert proof["operator_routes_public_validator_authority_claimed"] is False
    assert proof["operator_routes_public_poh_finalization_claimed"] is False

    for key, route in proof["operator_routes"].items():
        assert key.startswith("POST /v1/poh/operator/")
        assert route["metadata_source"] == "specs/api_contracts/v1_5_route_metadata.json"
        assert route["auth"] == "poh_operator_token_required_env_gated"
        assert "WEALL_ENABLE_OPERATOR_POH=true" in route["error_model"]
        assert "X-WeAll-Operator-Token" in route["error_model"]
        assert "public validator authority" in route["truth_boundary"]

    proc = subprocess.run(
        [sys.executable, "scripts/gen_api_contract_map.py", "--check"],
        cwd=str(ROOT),
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr


def test_storage_ipfs_durability_rejects_wrong_and_corrupt_content_without_public_media_claim() -> None:
    out = _proof()["storage_ipfs_durability_rehearsal"]
    assert out["ok"] is True
    assert out["worker_model"] == "multi_daemon_ipfs_compatible_operator_processes_with_failure_and_corruption_checks"
    assert out["daemon_count"] >= 3
    assert out["operator_failure_exercised"] is True
    assert out["reassignment_recorded"] is True
    assert out["wrong_cid_rejected"] is True
    assert out["corrupt_content_rejected_by_expected_hash"] is True
    assert out["retrieval_from_non_origin_operator_confirmed"] is True
    assert out["availability_status"] == "available"
    assert out["restricted_identity_evidence_boundary_preserved"] is True
    assert out["public_decentralized_media_claimed"] is False
    assert out["storage_provider_market_claimed"] is False
    assert out["automatic_evidence_deletion_claimed"] is False


def test_anti_sybil_suspicion_review_lifecycle_has_recovery_but_not_complete_sybil_claim() -> None:
    out = _proof()["anti_sybil_suspicion_review_lifecycle"]
    assert out["ok"] is True
    assert out["lifecycle_model"] == "anti_sybil_suspicion_to_review_to_appeal_recovery_without_auto_deletion"
    assert out["suspicion_record"]["recorded"] is True
    assert out["suspicion_record"]["review_window_close_height"] > out["suspicion_record"]["review_window_open_height"]
    assert out["follow_up_panel_assignment"]["selected_count"] >= 3
    assert out["false_positive_appeal_recovery_path"]["dismissed_adjudication"]["status"] == "adjudicated_dismissed"
    assert out["false_positive_appeal_recovery_path"]["evidence_deletion"]["deleted"] is True
    assert out["reviewer_accountability_record"]["scores_after_confirm"]
    assert out["reviewer_accountability_record"]["scores_after_dismiss"]
    assert out["no_automatic_duplicate_human_deletion"] is True
    assert out["duplicate_human_detection_claimed"] is False
    assert out["complete_anti_sybil_solved"] is False
    assert out["automatic_collusion_detection_claimed"] is False


def test_helper_equivalence_corpus_expands_without_production_activation() -> None:
    out = _proof()["helper_equivalence_corpus_expansion"]
    assert out["ok"] is True
    assert out["helper_eligible_domain_count"] >= 7
    assert out["tx_count"] >= 10
    assert out["serial_equivalence_ok"] is True
    assert out["missing_helper_fallback"] is True
    assert out["byzantine_helper_rejection"] is True
    assert out["deterministic_merge_preserves_tx_order"] is True
    assert out["state_root_equality_proven_by_serial_equivalence"] is True
    assert out["production_helper_execution_enabled"] is False
    assert out["public_helper_execution_claimed"] is False


def test_claim_boundaries_and_artifact_freshness() -> None:
    proof = _proof()
    assert proof["ok"] is True
    assert proof["controlled_testnet_candidate_strengthened"] is True
    assert proof["trusted_observer_candidate_strengthened"] is True
    assert proof["public_beta_ready"] is False
    assert proof["claim_boundaries"] == {
        "automatic_protocol_upgrades": False,
        "complete_anti_sybil_solved": False,
        "live_economics": False,
        "mainnet_readiness": False,
        "personalized_feed_ranking": False,
        "production_helper_execution": False,
        "public_beta_readiness": False,
        "public_decentralized_media_durability": False,
        "public_multi_validator_bft": False,
        "public_storage_provider_market": False,
        "public_validator_readiness": False,
    }
    proc = subprocess.run(
        [sys.executable, "scripts/gen_b582_b586_readiness_truth_and_proof_v1_5.py", "--check"],
        cwd=str(ROOT),
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr

    gate = subprocess.run(
        [sys.executable, "scripts/check_v15_public_readiness_artifacts.py"],
        cwd=str(ROOT),
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    assert gate.returncode == 0, gate.stdout + gate.stderr
