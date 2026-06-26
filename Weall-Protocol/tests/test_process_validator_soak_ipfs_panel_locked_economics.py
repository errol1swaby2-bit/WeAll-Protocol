from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PROOF = ROOT / "generated" / "b572_b576_multimachine_soak_proof_v1_5.json"


def _proof() -> dict:
    return json.loads(PROOF.read_text(encoding="utf-8"))


def test_batch572_independent_process_validator_network_rehearses_restart_and_roots() -> None:
    out = _proof()["independent_process_validator_network"]
    assert out["ok"] is True
    assert out["process_model"] == "independent_multiprocessing_validator_nodes"
    assert out["node_count"] == 4
    assert out["process_ids_unique"] is True
    assert out["proposal_vote_commit_rounds"] == 6
    assert out["restart_catchup_exercised"] is True
    assert set(out["heights_final"].values()) == {6}
    assert out["state_roots_match"] is True
    assert out["public_validator_readiness_claimed"] is False


def test_batch573_seeded_long_run_gossip_soak_exercises_restarts_partitions_reordering() -> None:
    out = _proof()["seeded_long_run_gossip_soak"]
    assert out["ok"] is True
    assert out["soak_model"] == "seeded_deterministic_long_run_autonomous_gossip"
    assert out["rounds"] >= 48
    assert out["restart_cycles"] >= 3
    assert out["partition_rejoin_cycles"] >= 4
    assert out["delayed_delivery_events"] > 0
    assert out["reorder_events"] > 0
    assert set(out["heights_final"].values()) == {out["rounds"]}
    assert out["state_roots_match"] is True
    assert out["public_validator_readiness_claimed"] is False


def test_batch574_multidaemon_ipfs_durability_uses_replacement_daemon_after_failure() -> None:
    out = _proof()["multidaemon_ipfs_durability"]
    assert out["ok"] is True
    assert out["worker_model"] == "multi_daemon_ipfs_compatible_operator_processes"
    assert out["daemon_count"] == 3
    assert out["failed_operator"] != out["replacement_operator"]
    assert out["failed_process_exitcode"] is not None
    assert out["operator_failure_exercised"] is True
    assert out["reassignment_recorded"] is True
    assert out["replacement_replicate_result"]["ok"] is True
    assert out["replacement_cat_result"]["ok"] is True
    assert out["retrieval_confirmed"] is True
    assert out["availability_status"] == "available"
    assert out["public_decentralized_media_claimed"] is False


def test_batch575_anti_sybil_signal_aggregation_and_panel_selection_are_deterministic() -> None:
    out = _proof()["anti_sybil_panel_signal_aggregation"]
    assert out["ok"] is True
    sig = out["signal_aggregation"]
    assert sig["requires_adjudication_panel"] is True
    assert sig["severity"] in {"medium", "high"}
    assert sig["automatic_duplicate_human_detection_claimed"] is False
    panel = out["panel_selection"]
    assert panel["deterministic_selection"] is True
    assert panel["selected_count"] == 3
    assert "reviewer-d" not in panel["selected_reviewers"]
    assert out["adjudication"]["status"] == "adjudicated_confirmed"
    assert out["evidence_deletion"]["deleted"] is True
    assert out["automatic_collusion_detection_claimed"] is False


def test_batch576_long_run_locked_economics_stress_keeps_economics_disabled() -> None:
    out = _proof()["long_run_locked_economics_stress"]
    assert out["ok"] is True
    stress = out["stress_summary"]
    assert stress["epochs"] >= 24
    assert stress["rejected_claim_count"] > 0
    assert stress["duplicate_work_rejections"] > 0
    assert stress["recipient_eligibility_rejections"] > 0
    assert stress["economics_enabled"] is False
    assert stress["live_mutation_enabled"] is False
    assert stress["transfer_before_activation"]["reason"] == "economics_disabled"
    assert out["failed_transfer_record"]["status"] == "failed"
    assert out["treasury_report"]["public_accountability_report"] is True
    assert out["live_economics_claimed"] is False


def test_batch572_576_claim_boundaries_and_artifact_freshness() -> None:
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
        [sys.executable, "scripts/gen_b572_b576_multimachine_soak_proof_v1_5.py", "--check"],
        cwd=str(ROOT),
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
