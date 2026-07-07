from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PROOF = ROOT / "generated" / "b539_b543_production_path_proof_v1_5.json"


def _proof() -> dict:
    return json.loads(PROOF.read_text(encoding="utf-8"))


def test_production_bft_path_uses_executor_methods_and_no_proof_endpoint() -> None:
    out = _proof()["production_bft_path"]
    assert out["ok"] is True
    assert out["proof_endpoint_used"] is False
    assert out["validator_count"] == 4
    assert out["vote_count"] >= out["quorum_threshold"]
    assert out["qc_formed"] is True
    assert out["state_roots_match"] is True
    methods = set(out["production_bft_methods_used"])
    assert "WeAllExecutor.bft_leader_propose" in methods
    assert "WeAllExecutor.bft_handle_vote" in methods
    assert "WeAllExecutor.produce_block" in methods
    assert "WeAllExecutor.apply_block" in methods


def test_production_block_commit_replay_uses_sqlite_tables_and_rejects_corruption() -> None:
    out = _proof()["production_block_replay"]
    assert out["ok"] is True
    assert out["production_commit_path"] is True
    assert out["source_db_backed"] is True
    assert out["fresh_replay_db_backed"] is True
    assert out["height"] >= 3
    assert out["state_roots_match"] is True
    assert out["corrupt_block_rejected"] is True
    assert set(out["block_commit_tables_used"]) >= {"blocks", "block_hash_index", "ledger_state"}
    assert out["source_table_counts"]["blocks"] == out["replay_table_counts"]["blocks"]


def test_public_api_write_lifecycle_reports_real_writes_and_remaining_direct_apply_domains() -> None:
    out = _proof()["public_api_write_lifecycle"]
    assert out["ok"] is True
    assert "POST /v1/tx/submit ACCOUNT_REGISTER" in out["api_write_routes_exercised"]
    assert "POST /v1/tx/submit CONTENT_POST_CREATE" in out["api_write_routes_exercised"]
    assert "GET /v1/feed?rank=production" in out["api_read_routes_exercised"]
    assert out["feed_rank_mode"] == "production"
    assert out["feed_items"] >= 1
    assert out["poh_challenge_status"] == "resolved"
    assert out["dispute_remedy_applied"] is True
    assert out["storage_retrieval_confirmed"] is True
    assert out["protocol_upgrade_record_only"] is True
    assert "poh_challenge" in out["direct_apply_write_domains_remaining"]


def test_live_storage_worker_durability_records_reassignment_and_retrieval() -> None:
    out = _proof()["live_storage_worker_durability"]
    assert out["ok"] is True
    assert out["worker_model"] == "local_operator_file_pin_worker"
    assert out["reassignment_recorded"] is True
    assert out["replacement_operator"] != out["failed_operator"]
    assert out["retrieval_confirmed"] is True
    assert out["availability_status"] == "available"
    assert out["retrieval_proof_count"] >= 1
    assert len(out["operator_file_sha256"]) == 64


def test_production_path_claim_boundaries_remain_locked() -> None:
    proof = _proof()
    assert proof["ok"] is True
    assert proof["claim_boundaries"] == {
        "automatic_protocol_upgrades": False,
        "live_economics": False,
        "mainnet_readiness": False,
        "production_helper_execution": False,
        "public_multi_validator_bft": False,
        "public_validator_readiness": False,
    }
    assert proof["remaining_public_testnet_gaps"]


def test_generated_artifact_is_fresh() -> None:
    proc = subprocess.run(
        [sys.executable, "scripts/gen_b539_b543_production_path_proof_v1_5.py", "--check"],
        cwd=str(ROOT),
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
