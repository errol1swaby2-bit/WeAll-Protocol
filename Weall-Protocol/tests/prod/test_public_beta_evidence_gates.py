from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def test_public_beta_blocker_report_is_conservative_and_complete() -> None:
    sys.path.insert(0, str(ROOT / "scripts"))
    sys.path.insert(0, str(ROOT / "src"))
    from gen_public_beta_blocker_report_v1_5 import build

    report = build()
    assert report["ok"] is True
    assert report["public_beta_ready"] is False
    assert report["mainnet_ready"] is False
    assert report["controlled_testnet_candidate"] is True
    assert report["blocker_count"] >= 13
    assert report["public_beta_blockers_remaining"] is True
    assert report["evidence_inventory_ok"] is True
    assert "ok_meaning" in report
    assert report["blocker_classification_summary"]["external_evidence_required"] >= 5
    assert report["blocker_classification_summary"]["closed_by_artifact_or_docs"] >= 3
    ids = {row["id"] for row in report["blockers"]}
    assert {
        "AUD-618-P0-001",
        "AUD-618-P0-002",
        "AUD-618-P0-003",
        "AUD-618-P1-001",
        "AUD-618-P1-002",
        "AUD-618-P1-003",
        "AUD-618-P1-004",
        "AUD-618-P1-005",
        "AUD-618-P1-006",
        "AUD-618-P2-001",
        "AUD-618-P2-002",
        "AUD-618-P2-003",
        "AUD-618-P3-001",
    }.issubset(ids)
    boundaries = report["release_claim_boundaries"]
    for key in (
        "public_validator_enabled",
        "production_helper_execution",
        "automatic_protocol_upgrades",
        "live_economics",
        "legal_compliance_ready",
    ):
        assert boundaries[key] is False
    assert report["evidence_gate_summaries"]["api_response_vectors"]["vector_count"] >= 24
    assert "public_validator_operator_transcript" in report["transcript_schemas"]
    assert "storage_ipfs_operator_transcript" in report["transcript_schemas"]
    assert "legal_attestation" in report["transcript_schemas"]
    by_id = {row["id"]: row for row in report["blockers"]}
    assert by_id["AUD-618-P0-003"]["blocker_category"] == "external_evidence_required"
    assert by_id["AUD-618-P1-006"]["blocker_category"] == "closed_by_artifact_or_docs"
    assert by_id["AUD-618-P2-001"]["blocker_category"] == "ux_or_observability_follow_up"


def test_generated_public_beta_blocker_report_is_fresh() -> None:
    proc = subprocess.run(
        [sys.executable, "scripts/gen_public_beta_blocker_report_v1_5.py", "--check"],
        cwd=str(ROOT),
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
    payload = json.loads((ROOT / "generated" / "public_beta_blocker_report_v1_5.json").read_text(encoding="utf-8"))
    assert payload["schema"] == "weall.v1_5.public_beta_blocker_report"
    assert payload["public_beta_ready"] is False


def test_api_response_vectors_are_expanded() -> None:
    proc = subprocess.run(
        [sys.executable, "scripts/gen_api_response_vectors_v1_5.py", "--check"],
        cwd=str(ROOT),
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
    payload = json.loads((ROOT / "generated" / "api_response_vectors_v1_5.json").read_text(encoding="utf-8"))
    assert payload["vector_count"] >= 24
    route_keys = {row["route_key"] for row in payload["vectors"]}
    assert "GET /v1/status/testnet-capabilities" in route_keys
    assert "GET /v1/status/operator" in route_keys
    assert "GET /v1/status/mempool" in route_keys
    assert "GET /v1/storage/ipfs/ops" in route_keys
    assert "GET /v1/tx/status/{tx_id}" in route_keys


def test_testnet_capabilities_surface_includes_public_beta_blocker_summary() -> None:
    from weall.runtime.testnet_capabilities import build_testnet_capability_surface

    surface = build_testnet_capability_surface({"params": {"launch_phase": "public_beta_candidate"}})
    summary = surface["public_beta_blocker_report"]
    assert summary["present"] is True
    assert summary["ok"] is True
    assert summary["public_beta_ready"] is False
    assert summary["mainnet_ready"] is False
    assert summary["blocker_count"] >= 13
    assert "public_validator_join" in surface["blocked_capabilities"]
    assert "production_helper_execution" in surface["blocked_capabilities"]
    assert surface["controlled_mechanism_artifact_blockers"] == []
    upgrade = surface["protocol_upgrade_lifecycle"]
    assert upgrade["activation_clock"] == "block_height"
    assert upgrade["activation_record_only"] is True
    assert upgrade["automatic_software_apply_enabled"] is False
    assert upgrade["economics_activation_enabled_by_upgrade"] is False
    assert "governance parent" in upgrade["truth_boundary"]
    assert surface["governance_lifecycle"]["scheduler"] == "tick_governance_lifecycle"
    assert surface["governance_lifecycle"]["manual_wall_clock_protocol_state_allowed"] is False
    assert surface["dispute_lifecycle"]["scheduler"] == "tick_dispute_lifecycle"
    assert surface["dispute_lifecycle"]["private_identity_evidence_publicly_exposed"] is False
    assert surface["minimum_reviewer_civic_loop"]["economics_locked_by_default"] is True


def test_controlled_go_gate_references_public_beta_blockers() -> None:
    proc = subprocess.run(
        [sys.executable, "scripts/run_controlled_testnet_go_gate_v1_5.py", "--check"],
        cwd=str(ROOT),
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
    payload = json.loads((ROOT / "generated" / "controlled_testnet_go_gate_v1_5.json").read_text(encoding="utf-8"))
    summary = payload["public_beta_blocker_report_summary"]
    assert summary["ok"] is True
    assert summary["public_beta_ready"] is False
    assert summary["mainnet_ready"] is False
    assert summary["blocker_count"] >= 13
    assert payload["controlled_testnet_go_gate_ready_to_run"] is True
    assert payload["controlled_testnet_candidate"] is True
    assert payload["public_readiness_claim_requires_external_evidence"] is True
