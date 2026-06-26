from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def test_batch620_external_operator_transcript_requirements_are_conservative() -> None:
    sys.path.insert(0, str(ROOT / "scripts"))
    from gen_external_operator_transcript_requirements_v1_5 import build

    payload = build()
    assert payload["ok"] is True
    assert payload["public_beta_ready"] is False
    assert payload["mainnet_ready"] is False
    assert payload["external_attestation_required_before_public_beta"] is True
    schemas = payload["schemas"]
    assert {"public_validator_operator_transcript", "storage_ipfs_operator_transcript", "legal_compliance_attestation"}.issubset(schemas)
    boundaries = payload["release_claim_boundaries"]
    for key in (
        "public_validator_enabled",
        "public_storage_provider_market",
        "production_helper_execution",
        "automatic_protocol_upgrades",
        "live_economics",
        "legal_compliance_ready",
    ):
        assert boundaries[key] is False


def test_batch620_generated_external_operator_transcript_requirements_are_fresh() -> None:
    proc = subprocess.run(
        [sys.executable, "scripts/gen_external_operator_transcript_requirements_v1_5.py", "--check"],
        cwd=str(ROOT),
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
    payload = json.loads((ROOT / "generated" / "external_operator_transcript_requirements_v1_5.json").read_text(encoding="utf-8"))
    assert payload["schema"] == "weall.v1_5.external_operator_transcript_requirements"


def test_batch620_validator_transcript_validator_accepts_scaffold(tmp_path: Path) -> None:
    sys.path.insert(0, str(ROOT / "scripts"))
    from rehearse_external_public_validator_operator_network_v1_5 import build_transcript

    transcript = build_transcript()
    transcript_path = tmp_path / "validator-transcript.json"
    transcript_path.write_text(json.dumps(transcript, indent=2, sort_keys=True), encoding="utf-8")
    proc = subprocess.run(
        [
            sys.executable,
            "scripts/validate_external_operator_transcript_v1_5.py",
            "--kind",
            "public_validator_operator_transcript",
            "--path",
            str(transcript_path),
        ],
        cwd=str(ROOT),
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert transcript["claim_boundaries"]["public_validator_enabled"] is False
    assert transcript["external_attestation_required"] is True


def test_batch620_storage_transcript_validator_accepts_scaffold(tmp_path: Path) -> None:
    sys.path.insert(0, str(ROOT / "scripts"))
    from rehearse_storage_ipfs_external_operator_topology_v1_5 import build_transcript

    transcript = build_transcript()
    transcript_path = tmp_path / "storage-transcript.json"
    transcript_path.write_text(json.dumps(transcript, indent=2, sort_keys=True), encoding="utf-8")
    proc = subprocess.run(
        [
            sys.executable,
            "scripts/validate_external_operator_transcript_v1_5.py",
            "--kind",
            "storage_ipfs_operator_transcript",
            "--path",
            str(transcript_path),
        ],
        cwd=str(ROOT),
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert transcript["claim_boundaries"]["public_decentralized_media_durability"] is False
    assert transcript["real_daemon_topology_required"] is True


def test_batch620_api_vectors_and_go_gate_reference_external_evidence() -> None:
    for script in (
        "gen_api_response_vectors_v1_5.py",
        "gen_public_beta_blocker_report_v1_5.py",
        "run_controlled_testnet_go_gate_v1_5.py",
    ):
        proc = subprocess.run(
            [sys.executable, f"scripts/{script}", "--check"],
            cwd=str(ROOT),
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        assert proc.returncode == 0, proc.stdout + proc.stderr
    vectors = json.loads((ROOT / "generated" / "api_response_vectors_v1_5.json").read_text(encoding="utf-8"))
    assert vectors["vector_count"] >= 40
    route_keys = {row["route_key"] for row in vectors["vectors"]}
    for route in (
        "POST /v1/consensus/attest/submit",
        "GET /v1/disputes/eligible",
        "GET /v1/chain/manifest",
        "GET /v1/economics/status",
        "GET /v1/treasury/status",
    ):
        assert route in route_keys
    gate = json.loads((ROOT / "generated" / "controlled_testnet_go_gate_v1_5.json").read_text(encoding="utf-8"))
    summary = gate["external_operator_transcript_requirements_summary"]
    assert summary["ok"] is True
    assert summary["schema_count"] >= 3
    assert summary["public_beta_ready"] is False
