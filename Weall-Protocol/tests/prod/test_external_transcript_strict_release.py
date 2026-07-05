from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
OUTER = ROOT.parent


def _canon(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"))


def _with_digest(payload: dict[str, Any]) -> dict[str, Any]:
    payload = dict(payload)
    payload["transcript_digest"] = hashlib.sha256(_canon({k: v for k, v in payload.items() if k != "transcript_digest"}).encode("utf-8")).hexdigest()
    return payload


def _run_validator(kind: str, path: Path, *, strict: bool = False) -> subprocess.CompletedProcess[str]:
    cmd = [sys.executable, "scripts/validate_external_operator_transcript_v1_5.py", "--kind", kind, "--path", str(path)]
    if strict:
        cmd.insert(cmd.index("--path"), "--strict-release")
    return subprocess.run(cmd, cwd=str(ROOT), text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)


def test_strict_release_rejects_validator_and_storage_scaffolds(tmp_path: Path) -> None:
    sys.path.insert(0, str(ROOT / "scripts"))
    from rehearse_external_public_validator_operator_network_v1_5 import build_transcript as build_validator
    from rehearse_storage_ipfs_external_operator_topology_v1_5 import build_transcript as build_storage

    for kind, payload in (
        ("public_validator_operator_transcript", build_validator()),
        ("storage_ipfs_operator_transcript", build_storage()),
    ):
        transcript = tmp_path / f"{kind}.json"
        transcript.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
        shape = _run_validator(kind, transcript)
        assert shape.returncode == 0, shape.stdout + shape.stderr
        strict = _run_validator(kind, transcript, strict=True)
        assert strict.returncode == 1
        assert "strict release mode rejects" in strict.stderr


def test_strict_release_accepts_attested_validator_transcript(tmp_path: Path) -> None:
    state_roots = {node: "f" * 64 for node in ("validator-alpha", "validator-beta", "validator-gamma", "validator-delta")}
    payload = _with_digest({
        "schema": "weall.v1_5.public_validator_operator_transcript",
        "blocker": "AUD-618-P0-001",
        "chain_id": "weall-public-beta-candidate-rehearsal-2026-06-alpha",
        "operator_ids": ["op-errol-alpha", "op-errol-beta", "op-errol-gamma", "op-errol-delta"],
        "node_ids": list(state_roots.keys()),
        "machine_ids": ["host-audit-alpha-001", "host-audit-beta-002", "host-audit-gamma-003", "host-audit-delta-004"],
        "rounds": 8,
        "threshold": 3,
        "fresh_clone": True,
        "node_registration": True,
        "node_operator_readiness": True,
        "validator_candidate_path": True,
        "readiness_receipt": True,
        "activation_rehearsal": True,
        "observer_bypass_rejected": True,
        "restart_fail_closed_without_chain_state_signing": True,
        "state_root_by_node": state_roots,
        "state_roots_match": True,
        "partition_rejoin": True,
        "minority_partition_cannot_finalize": True,
        "equivocation_rejected": True,
        "observer_vote_rejected": True,
        "fresh_node_catchup": True,
        "restart_replay": True,
        "operator_signatures": ["sig-ed25519-alpha-real-attestation-0001", "sig-ed25519-beta-real-attestation-0002", "sig-ed25519-gamma-real-attestation-0003", "sig-ed25519-delta-real-attestation-0004"],
        "external_attestation_attached": True,
        "operator_attestation": "external_operator_signed",
        "machine_isolation": "independent_machines",
        "claim_boundaries": {
            "public_validator_enabled": False,
            "public_multi_validator_bft": False,
            "public_beta_ready": False,
            "mainnet_ready": False,
            "live_economics_enabled": False,
        },
    })
    path = tmp_path / "validator-real.json"
    path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
    proc = _run_validator("public_validator_operator_transcript", path, strict=True)
    assert proc.returncode == 0, proc.stdout + proc.stderr


def test_strict_release_accepts_attested_storage_and_legal_transcripts(tmp_path: Path) -> None:
    storage = _with_digest({
        "schema": "weall.v1_5.storage_ipfs_operator_transcript",
        "blocker": "AUD-618-P1-004",
        "operator_ids": ["storage-alpha-real", "storage-beta-real", "storage-gamma-real"],
        "machine_ids": ["storage-host-alpha-001", "storage-host-beta-002", "storage-host-gamma-003"],
        "ipfs_peer_ids": ["12D3KooWalphaRealPeer111111", "12D3KooWbetaRealPeer222222", "12D3KooWgammaRealPeer333333"],
        "daemon_versions": {
            "storage-host-alpha-001": "kubo-v0.29.0-alpha-real",
            "storage-host-beta-002": "kubo-v0.29.0-beta-real",
            "storage-host-gamma-003": "kubo-v0.29.0-gamma-real",
        },
        "payload_sha256": "a" * 64,
        "cid": "bafybeigdyrztrealoperatorcidb621evidencecandidate",
        "replication_factor": 3,
        "publish_proofs": {"origin_machine": "storage-host-alpha-001", "add_sha256": "b" * 64},
        "pin_proofs": {
            "storage-host-alpha-001": "pin-proof-alpha-real-001",
            "storage-host-beta-002": "pin-proof-beta-real-002",
            "storage-host-gamma-003": "pin-proof-gamma-real-003",
        },
        "retrieval_proofs": {
            "storage-host-alpha-001": "a" * 64,
            "storage-host-beta-002": "a" * 64,
            "storage-host-gamma-003": "a" * 64,
        },
        "durability_window": {"started_utc": "2026-07-05T00:00:00Z", "ended_utc": "2026-07-05T00:30:00Z", "minimum_minutes": 30},
        "origin_failure": True,
        "retrieval_from_non_origin_machine": True,
        "fresh_node_retrieval": True,
        "wrong_cid_rejected": True,
        "corrupt_content_rejected": True,
        "revalidation_exercised": True,
        "operator_signatures": ["sig-storage-alpha-real-attestation-001", "sig-storage-beta-real-attestation-002", "sig-storage-gamma-real-attestation-003"],
        "external_attestation_attached": True,
        "real_daemon_topology": True,
        "operator_attestation": "external_storage_operator_signed",
        "claim_boundaries": {
            "public_storage_provider_market": False,
            "public_decentralized_media_durability": False,
            "public_beta_ready": False,
            "mainnet_ready": False,
        },
    })
    storage_path = tmp_path / "storage-real.json"
    storage_path.write_text(json.dumps(storage, indent=2, sort_keys=True), encoding="utf-8")
    storage_proc = _run_validator("storage_ipfs_operator_transcript", storage_path, strict=True)
    assert storage_proc.returncode == 0, storage_proc.stdout + storage_proc.stderr

    legal = _with_digest({
        "schema": "weall.v1_5.legal_compliance_attestation",
        "review_date": "2026-06-14",
        "reviewer_or_counsel_reference": "controlled-counsel-reference-2026-06-b621",
        "scope": ["public beta claims", "token/economics disabled claims", "governance language"],
        "approved_public_claims": ["controlled testnet candidate"],
        "restricted_claims": ["public beta ready", "mainnet ready", "live economics enabled"],
        "launch_matrix_checked": True,
        "signature_or_controlled_reference": "controlled-attestation-reference-b621-release-review",
        "counsel_or_control_attestation_attached": True,
        "claim_boundaries": {
            "legal_compliance_ready": False,
            "live_economics": False,
            "mainnet_ready": False,
        },
    })
    legal_path = tmp_path / "legal-real.json"
    legal_path.write_text(json.dumps(legal, indent=2, sort_keys=True), encoding="utf-8")
    legal_proc = _run_validator("legal_compliance_attestation", legal_path, strict=True)
    assert legal_proc.returncode == 0, legal_proc.stdout + legal_proc.stderr


def test_release_evidence_manifest_is_fresh_and_conservative() -> None:
    proc = subprocess.run(
        [sys.executable, "scripts/gen_release_evidence_manifest_v1_5.py", "--check"],
        cwd=str(ROOT),
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
    payload = json.loads((ROOT / "generated" / "release_evidence_manifest_v1_5.json").read_text(encoding="utf-8"))
    assert payload["schema"] == "weall.v1_5.release_evidence_manifest"
    assert payload["public_beta_ready"] is False
    assert payload["mainnet_ready"] is False
    assert payload["runtime_commit_binding_required"] is True
    assert payload["release_evidence_gates"]["external_validator_operator_transcript"]["sample_transcripts_are_rejected_in_strict_release"] is True


def test_clean_gate_reports_rendered_operator_journey_boundary() -> None:
    script = (OUTER / "scripts" / "run_clean_clone_go_gate_v1_5.sh").read_text(encoding="utf-8")
    assert "--run-rendered-frontend" in script
    assert "WEALL_RUN_RENDERED_FRONTEND" in script
    assert "Rendered operator journey check not run" in script
    assert "npm run test:rendered-operator-journey" in script
