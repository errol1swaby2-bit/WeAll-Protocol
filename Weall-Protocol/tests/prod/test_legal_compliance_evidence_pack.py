from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
TEMPLATE = ROOT / "docs" / "proofs" / "legal-compliance-counsel" / "2026-07-05" / "ATTESTATION_TEMPLATE.json"


def _run_validator(path: Path, *, strict: bool) -> subprocess.CompletedProcess[str]:
    cmd = [
        sys.executable,
        "scripts/validate_external_operator_transcript_v1_5.py",
        "--kind",
        "legal_compliance_attestation",
        "--path",
        str(path),
    ]
    if strict:
        cmd.insert(-2, "--strict-release")
    return subprocess.run(cmd, cwd=ROOT, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)


def _with_digest(payload: dict) -> dict:
    import hashlib
    base = {k: v for k, v in payload.items() if k != "transcript_digest"}
    payload["transcript_digest"] = hashlib.sha256(json.dumps(base, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()
    return payload


def test_legal_compliance_pack_documents_non_claim_boundary() -> None:
    evidence_pack = (ROOT / "docs" / "legal" / "COUNSEL_REVIEW_EVIDENCE_PACK.md").read_text(encoding="utf-8")
    runbook = (ROOT / "docs" / "testnet" / "LEGAL_COMPLIANCE_EVIDENCE_PACK.md").read_text(encoding="utf-8")
    status = (ROOT / "docs" / "reviewer" / "PUBLIC_BETA_BLOCKER_STATUS.md").read_text(encoding="utf-8")
    combined = "\n".join([evidence_pack, runbook, status]).lower()
    for phrase in (
        "non-lawyer draft",
        "pending counsel review",
        "not legal advice",
        "aud-618-p0-002 remains open",
        "live economics remain disabled",
        "public beta readiness remains unclaimed",
        "strict-release validation",
    ):
        assert phrase in combined


def test_legal_compliance_template_is_shape_valid_but_strict_release_rejected() -> None:
    payload = json.loads(TEMPLATE.read_text(encoding="utf-8"))
    assert payload["blocker"] == "AUD-618-P0-002"
    assert payload["sample_transcript_only"] is True
    assert payload["claim_boundaries"]["legal_compliance_ready"] is False
    assert payload["claim_boundaries"]["public_beta_ready"] is False

    shape_proc = _run_validator(TEMPLATE, strict=False)
    # Shape mode still rejects the placeholder launch_matrix_checked=false until a real reviewer fills it in.
    assert shape_proc.returncode != 0
    assert "launch_matrix_checked" in shape_proc.stderr

    strict_proc = _run_validator(TEMPLATE, strict=True)
    assert strict_proc.returncode != 0
    assert "sample_transcript_only=true" in strict_proc.stderr
    assert "counsel_or_control_attestation_attached=true" in strict_proc.stderr


def test_realistic_legal_compliance_attestation_passes_strict_release(tmp_path: Path) -> None:
    payload = _with_digest({
        "schema": "weall.v1_5.legal_compliance_attestation",
        "blocker": "AUD-618-P0-002",
        "review_date": "2026-07-05",
        "review_commit": "1234567890abcdef1234567890abcdef12345678",
        "review_branch": "refactor/executor-module-split",
        "reviewer_or_counsel_reference": "controlled-counsel-reference-2026-07-05",
        "counsel_or_control_attestation_attached": True,
        "scope": [
            "public claims",
            "token/economics disabled claims",
            "governance and treasury language",
            "privacy and public-only posture",
            "minors/safety/sanctions policy",
            "public validator and BFT claims",
            "storage/IPFS claims",
            "helper execution claims",
        ],
        "documents_reviewed": [
            "docs/legal/COUNSEL_REVIEW_EVIDENCE_PACK.md",
            "docs/legal/PUBLIC_CLAIMS_CHECKLIST.md",
            "docs/legal/TOKEN_MARKETING_GUARDRAILS.md",
            "docs/LAUNCH_DISABLED_FEATURE_MATRIX.md",
            "generated/launch_disabled_matrix_v1_5.json",
            "docs/reviewer/PUBLIC_BETA_BLOCKER_STATUS.md",
        ],
        "approved_public_claims": ["controlled internal/public-observer rehearsal candidate"],
        "restricted_claims": [
            "public beta ready",
            "mainnet ready",
            "live economics ready",
            "public validator safe",
            "public storage-market ready",
            "legal approval",
        ],
        "launch_matrix_checked": True,
        "launch_disabled_matrix": {
            "live_economics": False,
            "token_transfers": False,
            "fees": False,
            "staking": False,
            "validator_rewards": False,
            "slashing": False,
            "treasury_spending": False,
            "public_validator_enrollment": False,
            "public_multi_validator_bft": False,
            "automatic_protocol_upgrades": False,
            "protocol_migrations": False,
            "protocol_rollbacks": False,
            "production_helper_execution": False,
            "public_storage_market": False,
        },
        "signature_or_controlled_reference": "controlled-attestation-reference-2026-07-05",
        "claim_boundaries": {
            "legal_compliance_ready": False,
            "public_beta_ready": False,
            "mainnet_ready": False,
            "live_economics": False,
            "public_validator_enabled": False,
            "public_multi_validator_bft": False,
            "automatic_protocol_upgrades": False,
            "production_helper_execution": False,
            "public_storage_provider_market": False,
        },
    })
    path = tmp_path / "legal-attestation.json"
    path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
    proc = _run_validator(path, strict=True)
    assert proc.returncode == 0, proc.stdout + proc.stderr


def test_generated_external_requirements_and_manifest_reference_legal_pack() -> None:
    requirements = json.loads((ROOT / "generated" / "external_operator_transcript_requirements_v1_5.json").read_text(encoding="utf-8"))
    schema = requirements["schemas"]["legal_compliance_attestation"]
    assert schema["required_truths"]["blocker"] == "AUD-618-P0-002"
    assert schema["required_truths"]["launch_disabled_matrix.live_economics"] is False
    assert schema["minimum_counts"]["scope"] >= 8

    manifest = json.loads((ROOT / "generated" / "release_evidence_manifest_v1_5.json").read_text(encoding="utf-8"))
    gate = manifest["release_evidence_gates"]["legal_compliance_attestation"]
    assert gate["blocker"] == "AUD-618-P0-002"
    assert gate["evidence_pack"] == "docs/legal/COUNSEL_REVIEW_EVIDENCE_PACK.md"
    assert gate["template"] == "docs/proofs/legal-compliance-counsel/2026-07-05/ATTESTATION_TEMPLATE.json"
    assert gate["sample_templates_are_rejected_in_strict_release"] is True
