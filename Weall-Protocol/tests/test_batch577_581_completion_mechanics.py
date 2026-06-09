from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PROOF = ROOT / "generated" / "b577_b581_containerized_adversarial_proof_v1_5.json"


def _proof() -> dict:
    return json.loads(PROOF.read_text(encoding="utf-8"))


def test_batch577_containerized_validator_network_uses_independent_processes_ports_and_roots() -> None:
    out = _proof()["containerized_validator_network"]
    assert out["ok"] is True
    assert out["process_model"] == "containerized_local_port_independent_validator_nodes"
    assert out["node_count"] == 4
    assert out["ports_bound_count"] == 4
    assert out["process_ids_unique"] is True
    assert out["container_roots_created"] is True
    assert out["peer_discovery_configured"] is True
    assert out["mempool_gossip_exercised"] is True
    assert out["proposal_vote_qc_commit_exercised"] is True
    assert out["restart_catchup_exercised"] is True
    assert out["state_roots_match"] is True
    assert out["public_validator_readiness_claimed"] is False


def test_batch578_extended_soak_exercises_pressure_restarts_partitions_and_roots() -> None:
    out = _proof()["extended_seeded_network_soak"]
    assert out["ok"] is True
    assert out["soak_model"] == "extended_seeded_local_network_soak_with_resource_pressure"
    assert out["rounds"] >= 160
    assert out["restart_cycles"] >= 3
    assert out["partition_rejoin_cycles"] >= 5
    assert out["delayed_delivery_events"] > 0
    assert out["duplicate_delivery_events"] > 0
    assert out["resource_pressure_events"] > 0
    assert out["max_queue_depth"] >= out["rounds"]
    assert set(out["heights_final"].values()) == {out["rounds"]}
    assert out["state_roots_match"] is True
    assert out["public_validator_readiness_claimed"] is False


def test_batch579_real_ipfs_daemon_path_or_daemon_compatibility_records_retrieval_truth() -> None:
    out = _proof()["real_ipfs_daemon_durability"]
    assert out["ok"] is True
    assert out["worker_model"] == "real_ipfs_daemon_or_kubo_compatible_http_daemon"
    assert out["real_ipfs_daemon_requested"] is True
    assert out["daemon_mode"] in {"real_kubo_ipfs_daemon", "hermetic_ipfs_http_daemon_fallback"}
    assert isinstance(out["real_kubo_ipfs_daemon_used"], bool)
    assert out["ipfs_api_port_bound"] is True
    assert out["ipfs_api_port_label"] == "deterministic_local_test_port"
    assert out["cid"]
    assert out["pin_add_ok"] is True
    assert out["cat_ok"] is True
    assert out["retrieval_confirmed"] is True
    assert out["availability_status"] == "available"
    assert out["public_decentralized_media_claimed"] is False


def test_batch580_conflict_free_panel_appeal_and_evidence_deletion_execute() -> None:
    out = _proof()["anti_sybil_conflict_appeal_recovery"]
    assert out["ok"] is True
    assert out["signal_aggregation"]["requires_adjudication_panel"] is True
    assert out["panel_selection"]["conflict_exclusion_applied"] is True
    assert out["panel_selection"]["conflict_free_panel"] is True
    assert out["conflict_exclusion_worked"] is True
    assert out["adjudication"]["status"] == "adjudicated_confirmed"
    assert out["appeal"]["decision"] == "remedy_granted"
    assert out["appeal"]["recovery_applied"] is True
    assert out["evidence_deletion"]["deleted"] is True
    assert out["automatic_duplicate_human_detection_claimed"] is False
    assert out["automatic_collusion_detection_claimed"] is False


def test_batch581_economics_sybil_farming_stress_remains_locked() -> None:
    out = _proof()["economics_sybil_farming_adversarial_stress"]
    assert out["ok"] is True
    stress = out["stress_summary"]
    assert stress["epochs"] >= 48
    assert stress["sybil_account_count"] >= 6
    assert stress["rejected_claim_count"] > stress["accepted_claim_count"]
    assert stress["duplicate_or_ring_reuse_rejections"] > 0
    assert stress["sybil_recipient_rejections"] > 0
    assert stress["economics_enabled"] is False
    assert stress["live_mutation_enabled"] is False
    assert stress["balances_mutated"] is False
    assert out["treasury_report"]["public_accountability_report"] is True
    assert out["live_economics_claimed"] is False


def test_batch577_581_claim_boundaries_and_artifact_freshness() -> None:
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
        [sys.executable, "scripts/gen_b577_b581_containerized_adversarial_proof_v1_5.py", "--check"],
        cwd=str(ROOT),
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
