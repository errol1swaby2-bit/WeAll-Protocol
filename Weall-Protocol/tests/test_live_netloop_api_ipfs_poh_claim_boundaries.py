from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PROOF = ROOT / "generated" / "b544_b548_live_network_final_proof_v1_5.json"


def _proof() -> dict:
    return json.loads(PROOF.read_text(encoding="utf-8"))


def test_live_netloop_block_producer_uses_real_netloop_and_producer_surfaces() -> None:
    out = _proof()["live_netloop_block_producer"]
    assert out["ok"] is True
    assert out["net_loop_started"] is True
    assert out["net_loop_class"] == "weall.net.net_loop.NetMeshLoop"
    assert out["block_producer_surface_used"] == "weall.services.block_producer._produce_once"
    assert out["producer_delegate"] == "WeAllExecutor.produce_block"
    assert out["block_apply_surface_used"] == "WeAllExecutor.apply_block"
    assert out["produced_height"] >= 1
    assert out["state_roots_match"] is True
    assert out["public_validator_enabled"] is False


def test_api_system_lifecycle_closure_classifies_remaining_direct_apply_domains() -> None:
    out = _proof()["api_system_lifecycle_closure"]
    assert out["ok"] is True
    assert out["unclassified_remaining_domains"] == []
    classified = out["classified_remaining_domains"]
    assert classified["dispute_final_receipt"]["public_client_required"] is False
    assert classified["storage_receipt"]["public_client_required"] is False
    assert classified["protocol_upgrade_record"]["public_client_required"] is False
    assert out["public_client_write_gaps_remaining"] == ["poh_challenge"]
    assert out["protocol_upgrade_record_only"] is True


def test_live_ipfs_worker_durability_uses_worker_and_http_api() -> None:
    out = _proof()["live_ipfs_worker_durability"]
    assert out["ok"] is True
    assert out["worker_model"] == "IpfsPinWorker_with_local_http_ipfs_api"
    assert out["ipfs_enabled"] is True
    assert out["failure_api_requests"] >= 1
    assert out["success_api_requests"] >= 1
    assert out["failed_worker_stats"]["failed"] == 1
    assert out["replacement_worker_stats"]["pinned"] == 1
    assert out["reassignment_recorded"] is True
    assert out["retrieval_confirmed"] is True
    assert out["availability_status"] == "available"


def test_poh_dispute_adversarial_accountability_and_remedy() -> None:
    out = _proof()["poh_dispute_adversarial_accountability"]
    assert out["ok"] is True
    poh = out["poh_reviewer_accountability"]
    assert poh["reviewer_eligible_after_upheld_challenge"] is False
    assert poh["dismissed_consequence"]["type"] == "none"
    assert poh["reverification_required"] is True
    dispute = out["dispute_juror_accountability_and_remedy"]
    assert dispute["juror_ineligible_after_missed_vote"] is True
    assert dispute["juror_eligible_after_remedy"] is True
    assert dispute["target_reinstated"] is True
    assert out["collusion_detection_claimed"] is False
    assert out["duplicate_human_detection_claimed"] is False


def test_claim_boundaries_remain_conservative() -> None:
    proof = _proof()
    assert proof["ok"] is True
    assert proof["controlled_testnet_rehearsal_candidate"] is True
    assert proof["public_beta_ready"] is False
    assert proof["claim_boundaries"] == {
        "automatic_protocol_upgrades": False,
        "live_economics": False,
        "mainnet_readiness": False,
        "personalized_feed_ranking": False,
        "production_helper_execution": False,
        "public_multi_validator_bft": False,
        "public_validator_readiness": False,
    }
    assert proof["remaining_public_testnet_gaps"]


def test_generated_artifact_is_fresh() -> None:
    proc = subprocess.run(
        [sys.executable, "scripts/gen_b544_b548_live_network_final_proof_v1_5.py", "--check"],
        cwd=str(ROOT),
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
