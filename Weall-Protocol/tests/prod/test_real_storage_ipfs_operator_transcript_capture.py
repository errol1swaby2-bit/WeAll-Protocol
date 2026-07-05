from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]


def _run(*args: str) -> subprocess.CompletedProcess[str]:
    env = os.environ.copy()
    env.pop("PYTEST_CURRENT_TEST", None)
    env.setdefault("PYTHONDONTWRITEBYTECODE", "1")
    return subprocess.run(
        [*args],
        cwd=ROOT,
        env=env,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        timeout=45,
    )


def _read(rel: str) -> str:
    return (ROOT / rel).read_text(encoding="utf-8")


def _digest_without_self(payload: dict[str, Any]) -> str:
    material = {k: v for k, v in payload.items() if k != "transcript_digest"}
    return hashlib.sha256(json.dumps(material, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()


def _sample_storage_transcript() -> dict[str, Any]:
    payload: dict[str, Any] = {
        "schema": "weall.v1_5.storage_ipfs_operator_transcript",
        "blocker": "AUD-618-P1-004",
        "operator_ids": ["storage-alpha-real-20260705", "storage-beta-real-20260705", "storage-gamma-real-20260705"],
        "machine_ids": ["storage-host-alpha-20260705", "storage-host-beta-20260705", "storage-host-gamma-20260705"],
        "ipfs_peer_ids": ["12D3KooWalphaRealPeer20260705", "12D3KooWbetaRealPeer20260705", "12D3KooWgammaRealPeer20260705"],
        "daemon_versions": {
            "storage-host-alpha-20260705": "kubo-v0.29.0-alpha-real",
            "storage-host-beta-20260705": "kubo-v0.29.0-beta-real",
            "storage-host-gamma-20260705": "kubo-v0.29.0-gamma-real",
        },
        "payload_sha256": "a" * 64,
        "cid": "bafybeigdyrztrealoperatorcidb621evidencecandidate",
        "replication_factor": 3,
        "publish_proofs": {"origin_machine": "storage-host-alpha-20260705", "ipfs_add_output_sha256": "b" * 64},
        "pin_proofs": {
            "storage-host-alpha-20260705": "pin-proof-alpha-real-001",
            "storage-host-beta-20260705": "pin-proof-beta-real-002",
            "storage-host-gamma-20260705": "pin-proof-gamma-real-003",
        },
        "retrieval_proofs": {
            "storage-host-alpha-20260705": "a" * 64,
            "storage-host-beta-20260705": "a" * 64,
            "storage-host-gamma-20260705": "a" * 64,
        },
        "durability_window": {"started_utc": "2026-07-05T00:00:00Z", "ended_utc": "2026-07-05T00:30:00Z", "minimum_minutes": 30},
        "origin_failure": True,
        "retrieval_from_non_origin_machine": True,
        "fresh_node_retrieval": True,
        "wrong_cid_rejected": True,
        "corrupt_content_rejected": True,
        "revalidation_exercised": True,
        "real_daemon_topology": True,
        "external_attestation_attached": True,
        "operator_attestation": "external_storage_operator_signed",
        "operator_signatures": ["sig-storage-alpha-real-attestation-001", "sig-storage-beta-real-attestation-002", "sig-storage-gamma-real-attestation-003"],
        "claim_boundaries": {
            "public_storage_provider_market": False,
            "public_decentralized_media_durability": False,
            "public_beta_ready": False,
            "mainnet_ready": False,
            "live_economics": False,
            "automatic_protocol_upgrades": False,
            "production_helper_execution": False,
            "legal_compliance_ready": False,
        },
    }
    payload["transcript_digest"] = _digest_without_self(payload)
    return payload


def test_real_storage_ipfs_capture_script_is_helpful_and_non_authoritative() -> None:
    script = ROOT / "scripts" / "capture_real_storage_ipfs_operator_transcript_v1_5.sh"
    assert script.is_file()
    assert os.access(script, os.X_OK)
    text = script.read_text(encoding="utf-8")
    for required in [
        "AUD-618-P1-004",
        "does not close AUD-618-P1-004",
        "LOCAL_STORAGE_IPFS_EVIDENCE.json",
        "wrong-CID rejection",
        "corrupt-content rejection",
        "real_daemon_topology",
        "public_decentralized_media_durability",
        "external_review_required_before_closure",
    ]:
        assert required in text

    proc = _run("bash", "scripts/capture_real_storage_ipfs_operator_transcript_v1_5.sh", "--help")
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "Captures one real IPFS/Kubo daemon evidence packet" in proc.stdout
    assert "does not close AUD-618-P1-004" in proc.stdout


def test_real_storage_ipfs_docs_and_template_keep_blocker_open() -> None:
    runbook = _read("docs/testnet/REAL_STORAGE_IPFS_OPERATOR_TRANSCRIPT.md")
    readme = _read("docs/proofs/real-storage-ipfs-operator/2026-07-05/README.md")
    template = _read("docs/proofs/real-storage-ipfs-operator/2026-07-05/TRANSCRIPT_TEMPLATE.json")
    first_15 = _read("docs/testnet/FIRST_15_MINUTES.md")
    status = _read("docs/reviewer/PUBLIC_BETA_BLOCKER_STATUS.md")

    for text in [runbook, readme, template, first_15, status]:
        assert "AUD-618-P1-004" in text
    assert "Local simulations" in runbook
    assert "Status: TEMPLATE ONLY" in readme
    assert "storage_ipfs_operator_transcript" in template
    assert "wrong_cid_rejected" in template
    assert "corrupt_content_rejected" in template
    assert "public_storage_provider_market" in template
    assert "strict-release validation" in status


def test_real_storage_ipfs_schema_and_validator_accept_real_shape(tmp_path: Path) -> None:
    proc = _run(sys.executable, "scripts/gen_external_operator_transcript_requirements_v1_5.py", "--check")
    assert proc.returncode == 0, proc.stdout + proc.stderr
    payload = json.loads((ROOT / "generated" / "external_operator_transcript_requirements_v1_5.json").read_text(encoding="utf-8"))
    schemas = payload["schemas"]
    assert "storage_ipfs_operator_transcript" in schemas
    schema = schemas["storage_ipfs_operator_transcript"]
    assert "payload_sha256" in schema["required_fields"]
    assert "retrieval_proofs" in schema["required_fields"]
    assert schema["required_truths"]["blocker"] == "AUD-618-P1-004"
    assert payload["public_beta_ready"] is False

    transcript_path = tmp_path / "storage-ipfs-operator-transcript.json"
    transcript_path.write_text(json.dumps(_sample_storage_transcript(), indent=2, sort_keys=True), encoding="utf-8")
    validate = _run(
        sys.executable,
        "scripts/validate_external_operator_transcript_v1_5.py",
        "--kind",
        "storage_ipfs_operator_transcript",
        "--strict-release",
        "--path",
        str(transcript_path),
    )
    assert validate.returncode == 0, validate.stdout + validate.stderr


def test_public_beta_and_release_artifacts_reference_real_storage_ipfs_capture() -> None:
    for script in (
        "gen_release_evidence_manifest_v1_5.py",
        "gen_public_beta_blocker_report_v1_5.py",
    ):
        proc = _run(sys.executable, f"scripts/{script}", "--check")
        assert proc.returncode == 0, proc.stdout + proc.stderr

    report = json.loads((ROOT / "generated" / "public_beta_blocker_report_v1_5.json").read_text(encoding="utf-8"))
    blockers = {row["id"]: row for row in report["blockers"]}
    blocker = blockers["AUD-618-P1-004"]
    assert blocker["gate_status"] == "gate_present_real_operator_rehearsal_required"
    assert blocker["can_be_closed_by_code_only"] is False
    assert "real IPFS daemon transcript" in blocker["remaining_external_evidence"]
    assert report["public_beta_ready"] is False

    manifest = json.loads((ROOT / "generated" / "release_evidence_manifest_v1_5.json").read_text(encoding="utf-8"))
    gate = manifest["release_evidence_gates"]["storage_ipfs_operator_transcript"]
    assert gate["blocker"] == "AUD-618-P1-004"
    assert gate["required_before_public_beta"] is True
    assert gate["required_before_public_storage_claims"] is True
    assert "capture_real_storage_ipfs_operator_transcript_v1_5.sh" in gate["capture_script"]
