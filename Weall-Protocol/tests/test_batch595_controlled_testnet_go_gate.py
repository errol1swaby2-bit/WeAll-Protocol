from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

from weall.runtime.testnet_capabilities import build_testnet_capability_surface

ROOT = Path(__file__).resolve().parents[1]
PROOF = ROOT / "generated" / "controlled_testnet_go_gate_v1_5.json"


def _proof() -> dict:
    return json.loads(PROOF.read_text(encoding="utf-8"))


def test_batch595_controlled_testnet_go_gate_manifest_is_fresh_and_bounded() -> None:
    proof = _proof()
    assert proof["schema"] == "weall.v1_5.controlled_testnet_go_gate"
    assert proof["ok"] is True
    assert proof["controlled_testnet_go_gate_ready_to_run"] is True
    assert proof["controlled_private_testnet_candidate"] is True
    assert proof["controlled_testnet_ready_claimed_by_repo"] is False
    assert proof["public_beta_ready"] is False
    assert proof["public_readiness_claim_requires_external_evidence"] is True

    boundaries = proof["claim_boundaries"]
    for key in (
        "automatic_protocol_upgrades",
        "complete_anti_sybil_resistance",
        "legal_compliance_ready",
        "live_economics",
        "mainnet_readiness",
        "production_helper_execution",
        "public_beta_readiness",
        "public_decentralized_media_durability",
        "public_multi_validator_bft",
        "public_storage_provider_market",
        "public_validator_readiness",
        "protocol_private_activity",
    ):
        assert boundaries[key] is False

    proc = subprocess.run(
        [sys.executable, "scripts/run_controlled_testnet_go_gate_v1_5.py", "--check"],
        cwd=str(ROOT),
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr


def test_batch595_go_gate_captures_required_artifact_and_runtime_evidence() -> None:
    proof = _proof()
    artifacts = proof["artifact_inputs"]
    for rel in (
        "generated/api_contract_map_v1_5.json",
        "generated/failure_code_registry_v1_5.json",
        "generated/api_response_vectors_v1_5.json",
        "generated/b587_b594_testnet_mechanism_completion_v1_5.json",
    ):
        assert artifacts[rel]["present"] is True
        assert artifacts[rel]["ok"] is True

    assert proof["api_response_vector_summary"]["vector_count"] >= 10
    assert proof["b587_b594_mechanism_completion_summary"]["controlled_testnet_mechanisms_complete"] is True
    assert proof["b587_b594_mechanism_completion_summary"]["public_beta_ready"] is False
    assert proof["validator_go_gate_snapshot"]["state_roots_match"] is True
    assert proof["validator_go_gate_snapshot"]["requires_independent_operator_run"] is True
    assert proof["storage_go_gate_snapshot"]["fresh_node_retrieval_path_exercised"] is True
    assert proof["storage_go_gate_snapshot"]["requires_real_operator_rehearsal"] is True


def test_batch595_launch_capability_surface_includes_mechanism_completion_artifact() -> None:
    surface = build_testnet_capability_surface({"params": {"launch_phase": "public_beta_candidate"}})
    artifacts = surface["required_artifacts"]
    assert artifacts["b587_b594_mechanism_completion"]["present"] is True
    assert artifacts["b587_b594_mechanism_completion"]["ok"] is True
    assert surface["controlled_testnet_mechanisms_complete"] is True
    assert surface["public_beta_ready_claimed"] is False
    for cap in (
        "live_transfers",
        "live_rewards",
        "treasury_spend",
        "live_economics",
        "public_validator_join",
        "public_multi_validator_bft",
        "automatic_protocol_upgrade_apply",
        "production_helper_execution",
    ):
        assert surface["capabilities"][cap]["enabled"] is False
        assert surface["capabilities"][cap]["blocked_by_launch_matrix"] is True


def test_batch595_readiness_artifact_gate_includes_go_gate_manifest() -> None:
    result = subprocess.run(
        [sys.executable, "scripts/check_v15_public_readiness_artifacts.py"],
        cwd=str(ROOT),
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert "release-safe" in result.stdout
