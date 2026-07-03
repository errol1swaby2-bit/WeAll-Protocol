from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

from weall.runtime.testnet_capabilities import build_testnet_capability_surface

ROOT = Path(__file__).resolve().parents[1]
PROOF = ROOT / "generated" / "b587_b594_testnet_mechanism_completion_v1_5.json"


def _proof() -> dict:
    return json.loads(PROOF.read_text(encoding="utf-8"))


def test_api_response_vectors_cover_sensitive_routes_without_public_beta_claim() -> None:
    proof = _proof()["api_response_vectors"]
    assert proof["ok"] is True
    assert proof["vector_count"] >= 10
    route_keys = {v["route_key"] for v in proof["vectors"]}
    assert "GET /v1/session/me" in route_keys
    assert "GET /v1/activity/notices" in route_keys
    assert "GET /v1/" + "mess" + "ages/threads" not in route_keys
    assert "GET /v1/poh/async/case/{case_id}" in route_keys
    assert "POST /v1/poh/operator/live/init" in route_keys
    assert "POST /v1/tx/submit" in route_keys
    assert proof["truth_boundaries"]["public_beta_ready"] is False
    assert proof["truth_boundaries"]["live_economics_enabled"] is False

    proc = subprocess.run(
        [sys.executable, "scripts/gen_api_response_vectors_v1_5.py", "--check"],
        cwd=str(ROOT),
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr


def test_launch_matrix_capability_surface_blocks_high_risk_features() -> None:
    surface = build_testnet_capability_surface({"params": {"launch_phase": "public_beta_candidate"}})
    assert surface["controlled_testnet_mechanisms_complete"] is True
    assert surface["public_beta_ready_claimed"] is False
    for key in (
        "live_transfers",
        "live_rewards",
        "treasury_spend",
        "live_economics",
        "public_validator_join",
        "public_multi_validator_bft",
        "automatic_protocol_upgrade_apply",
        "production_helper_execution",
    ):
        record = surface["capabilities"][key]
        assert record["enabled"] is False
        assert record["blocked_by_launch_matrix"] is True
        assert record["disabled_reason"]
    assert surface["truth_boundaries"] == {
        "automatic_protocol_upgrades_enabled": False,
        "launch_matrix_is_guardrail_not_consensus": True,
        "legal_compliance_ready_claimed": False,
        "live_economics_enabled": False,
        "production_helper_execution_enabled": False,
        "public_validator_enabled": False,
    }
    assert surface["governance_lifecycle"]["progression_clock"] == "block_height"
    assert surface["dispute_lifecycle"]["progression_clock"] == "block_height"
    assert surface["minimum_reviewer_civic_loop"]["public_only_visibility"] is True


def test_protocol_upgrade_signed_staging_verifies_without_execution() -> None:
    out = _proof()["protocol_upgrade_signed_staging"]
    assert out["ok"] is True
    assert out["valid_manifest_verified"] is True
    assert out["tampered_manifest_rejected"] is True
    assert out["wrong_signer_rejected"] is True
    assert out["auto_apply_rejected"] is True
    assert out["operator_action_required"] is True
    assert out["automatic_protocol_upgrade_enabled"] is False
    assert out["side_effects"] == {
        "artifact_fetched": False,
        "migration_executed": False,
        "node_restarted": False,
        "rollback_executed": False,
        "software_applied": False,
    }


def test_external_multimachine_validator_harness_keeps_public_claims_false() -> None:
    out = _proof()["external_multimachine_validator_harness"]
    assert out["ok"] is True
    assert out["node_count"] == 4
    assert out["machine_count"] == 4
    assert out["partition_rejoin_exercised"] is True
    assert out["minority_partition_cannot_finalize"] is True
    assert out["equivocation_rejected"] is True
    assert out["observer_vote_rejected"] is True
    assert out["state_roots_match"] is True
    assert out["public_validator_enabled"] is False
    assert out["public_validator_readiness_claimed"] is False
    assert out["requires_independent_operator_run"] is True


def test_multimachine_storage_durability_keeps_public_media_claim_false() -> None:
    out = _proof()["multimachine_storage_ipfs_durability"]
    assert out["ok"] is True
    assert out["machine_count"] >= 5
    assert out["origin_failure_exercised"] is True
    assert out["replication_factor_after_reassignment"] >= 4
    assert out["retrieval_from_non_origin_machine"] is True
    assert out["wrong_cid_rejected"] is True
    assert out["corrupt_content_rejected_by_hash"] is True
    assert out["fresh_node_retrieval_path_exercised"] is True
    assert out["public_decentralized_media_durability_claimed"] is False
    assert out["requires_real_operator_rehearsal"] is True


def test_reviewer_accountability_appeal_and_evidence_deletion_mechanism() -> None:
    out = _proof()["reviewer_accountability_and_appeal"]
    assert out["ok"] is True
    assert out["conflict_exclusion_applied"] is True
    assert out["adjudication"]["status"] == "confirmed"
    assert out["penalty_record"]["automatic_deletion"] is False
    assert out["appeal"]["decision"] == "partial_remedy"
    assert out["false_positive_recovery"]["restriction_removed"] is True
    assert out["evidence_deletion"]["restricted_identity_evidence_deleted"] is True
    assert out["no_automatic_duplicate_human_deletion"] is True
    assert out["complete_anti_sybil_resistance_claimed"] is False


def test_helper_block_path_adversarial_remains_disabled() -> None:
    out = _proof()["helper_block_path_adversarial"]
    assert out["ok"] is True
    assert out["tx_count"] >= 4
    assert out["serial_equivalence_ok"] is True
    assert out["byzantine_helper_output_rejected"] is True
    assert out["missing_helper_fallback_to_serial"] is True
    assert out["restart_replay_root_equal"] is True
    assert out["deterministic_merge_preserves_tx_order"] is True
    assert out["production_helper_execution_enabled"] is False
    assert out["public_helper_execution_claimed"] is False


def test_locked_economics_adversarial_expansion_keeps_balances_unchanged() -> None:
    out = _proof()["locked_economics_adversarial_expansion"]
    assert out["ok"] is True
    assert out["epochs_simulated"] >= 72
    assert out["rejected_reward_claims"] == out["attempted_reward_claims"]
    assert out["accepted_reward_claims"] == 0
    assert out["balances_mutated"] is False
    assert out["treasury_attack"]["accepted"] is False
    assert out["validator_reward_concentration_attack"]["accepted"] is False
    assert out["fee_market_attack"]["accepted"] is False
    assert out["live_economics_enabled"] is False
    assert out["legal_compliance_ready_claimed"] is False


def test_mechanism_completion_artifact_freshness_and_boundaries() -> None:
    proof = _proof()
    assert proof["ok"] is True
    assert proof["controlled_testnet_mechanisms_complete"] is True
    assert proof["controlled_testnet_ready_candidate"] is True
    assert proof["public_beta_ready"] is False
    assert proof["public_readiness_claim_requires_external_gate_run"] is True
    assert proof["claim_boundaries"] == {
        "automatic_protocol_upgrades": False,
        "complete_anti_sybil_solved": False,
        "legal_compliance_ready": False,
        "live_economics": False,
        "mainnet_readiness": False,
        "production_helper_execution": False,
        "public_beta_readiness": False,
        "public_decentralized_media_durability": False,
        "public_multi_validator_bft": False,
        "public_storage_provider_market": False,
        "public_validator_readiness": False,
        "protocol_private_activity": False,
    }
    proc = subprocess.run(
        [sys.executable, "scripts/gen_b587_b594_testnet_mechanism_completion_v1_5.py", "--check"],
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


def test_minimum_reviewer_civic_loop_uses_canonical_frontend_routes() -> None:
    surface = build_testnet_capability_surface({"params": {"launch_phase": "public_beta_candidate"}})
    loop = surface["minimum_reviewer_civic_loop"]
    entrypoints = loop["frontend_entrypoints"]
    assert entrypoints["governance"] == "/decisions"
    assert entrypoints["governance_create"] == "/decisions/create"
    assert entrypoints["disputes"] == "/reports"
    assert entrypoints["review_center"] == "/reviews"
    assert entrypoints["node_status"] == "/node"
    assert entrypoints["economics"] == "/economics"
    assert "/proposals" not in entrypoints.values()
    assert "/disputes" not in entrypoints.values()
    assert loop["canonical_route_boundary"] == {
        "governance_label": "Decisions",
        "governance_route": "/decisions",
        "dispute_label": "Reports",
        "dispute_route": "/reports",
        "legacy_aliases_removed": ["/proposals", "/disputes"],
    }

    router_src = (ROOT.parent / "web" / "src" / "lib" / "router.ts").read_text(encoding="utf-8")
    for key, href in entrypoints.items():
        if ":" in href:
            continue
        assert f'"{href}"' in router_src, f"{key} points to a route not present in router.ts: {href}"
    assert '"/proposals"' not in router_src
    assert '"/disputes"' not in router_src
