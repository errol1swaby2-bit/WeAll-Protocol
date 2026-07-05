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


def _sample_validator_transcript() -> dict[str, Any]:
    roots = {
        "validator-node-alpha-real": "d" * 64,
        "validator-node-beta-real": "d" * 64,
        "validator-node-gamma-real": "d" * 64,
        "validator-node-delta-real": "d" * 64,
    }
    payload: dict[str, Any] = {
        "schema": "weall.v1_5.public_validator_operator_transcript",
        "blocker": "AUD-618-P0-001",
        "chain_id": "weall-testnet-v1",
        "commit": "0123456789abcdef0123456789abcdef01234567",
        "branch": "refactor/executor-module-split",
        "operator_ids": [
            "external-validator-operator-alpha-20260705",
            "external-validator-operator-beta-20260705",
            "external-validator-operator-gamma-20260705",
            "external-validator-operator-delta-20260705",
        ],
        "node_ids": list(roots.keys()),
        "machine_ids": [
            "external-validator-machine-alpha-20260705",
            "external-validator-machine-beta-20260705",
            "external-validator-machine-gamma-20260705",
            "external-validator-machine-delta-20260705",
        ],
        "machine_isolation": "independent_machines",
        "operator_attestation": "external_operator_signed",
        "external_attestation_attached": True,
        "rounds": 6,
        "threshold": 3,
        "fresh_clone": True,
        "node_registration": True,
        "node_operator_readiness": True,
        "validator_candidate_path": True,
        "readiness_receipt": True,
        "activation_rehearsal": True,
        "observer_bypass_rejected": True,
        "observer_vote_rejected": True,
        "restart_fail_closed_without_chain_state_signing": True,
        "restart_replay": True,
        "partition_rejoin": True,
        "minority_partition_cannot_finalize": True,
        "equivocation_rejected": True,
        "fresh_node_catchup": True,
        "state_roots_match": True,
        "state_root_by_node": roots,
        "operator_signatures": [
            "sig-validator-alpha-real-attestation-20260705-0001",
            "sig-validator-beta-real-attestation-20260705-0002",
            "sig-validator-gamma-real-attestation-20260705-0003",
            "sig-validator-delta-real-attestation-20260705-0004",
        ],
        "claim_boundaries": {
            "public_validator_enabled": False,
            "public_multi_validator_bft": False,
            "public_beta_ready": False,
            "mainnet_ready": False,
            "live_economics_enabled": False,
            "automatic_protocol_upgrades": False,
            "production_helper_execution": False,
            "legal_compliance_ready": False,
        },
    }
    payload["transcript_digest"] = _digest_without_self(payload)
    return payload


def test_independent_validator_capture_script_is_helpful_and_non_authoritative(tmp_path: Path) -> None:
    script = ROOT / "scripts" / "capture_independent_controlled_validator_operator_transcript_v1_5.sh"
    assert script.is_file()
    assert os.access(script, os.X_OK)
    text = script.read_text(encoding="utf-8")
    for required in [
        "AUD-618-P0-001",
        "does not close AUD-618-P0-001",
        "does not enable public validator admission",
        "does not grant signing authority through local flags",
        "observer bypass/vote rejection",
        "restart fail-closed proof unless chain state permits signing",
        "LOCAL_VALIDATOR_OPERATOR_EVIDENCE.json",
        "external_review_required_before_closure",
    ]:
        assert required in text

    help_proc = _run("bash", "scripts/capture_independent_controlled_validator_operator_transcript_v1_5.sh", "--help")
    assert help_proc.returncode == 0, help_proc.stdout + help_proc.stderr
    assert "Captures one machine's independent controlled validator/operator rehearsal evidence packet" in help_proc.stdout
    assert "does not close AUD-618-P0-001" in help_proc.stdout

    out_dir = tmp_path / "validator-packet"
    proc = _run(
        "bash",
        "scripts/capture_independent_controlled_validator_operator_transcript_v1_5.sh",
        "--operator-id",
        "external-validator-operator-alpha-20260705",
        "--machine-id",
        "external-validator-machine-alpha-20260705",
        "--node-id",
        "external-validator-node-alpha-20260705",
        "--out-dir",
        str(out_dir),
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
    packet = json.loads((out_dir / "LOCAL_VALIDATOR_OPERATOR_EVIDENCE.json").read_text(encoding="utf-8"))
    assert packet["blocker"] == "AUD-618-P0-001"
    assert packet["claim_boundaries"]["public_validator_enabled"] is False
    assert packet["external_review_required_before_closure"] is True


def test_independent_validator_docs_and_template_keep_blocker_open() -> None:
    runbook = _read("docs/testnet/INDEPENDENT_CONTROLLED_VALIDATOR_OPERATOR_TRANSCRIPT.md")
    readme = _read("docs/proofs/independent-controlled-validator-operator/2026-07-05/README.md")
    template = _read("docs/proofs/independent-controlled-validator-operator/2026-07-05/TRANSCRIPT_TEMPLATE.json")
    first_15 = _read("docs/testnet/FIRST_15_MINUTES.md")
    status = _read("docs/reviewer/PUBLIC_BETA_BLOCKER_STATUS.md")

    for text in [runbook, readme, template, first_15, status]:
        assert "AUD-618-P0-001" in text
    assert "remains open" in runbook
    assert "Status: TEMPLATE ONLY" in readme
    assert "fresh_clone" in template
    assert "validator_candidate_path" in template
    assert "restart_fail_closed_without_chain_state_signing" in template
    assert "public_multi_validator_bft" in template
    assert "only external evidence" in status


def test_independent_validator_schema_and_validator_accept_real_shape(tmp_path: Path) -> None:
    proc = _run(sys.executable, "scripts/gen_external_operator_transcript_requirements_v1_5.py", "--check")
    assert proc.returncode == 0, proc.stdout + proc.stderr
    payload = json.loads((ROOT / "generated" / "external_operator_transcript_requirements_v1_5.json").read_text(encoding="utf-8"))
    schema = payload["schemas"]["public_validator_operator_transcript"]
    assert "fresh_clone" in schema["required_fields"]
    assert "node_registration" in schema["required_fields"]
    assert "validator_candidate_path" in schema["required_fields"]
    assert schema["required_truths"]["blocker"] == "AUD-618-P0-001"
    assert payload["public_beta_ready"] is False

    transcript_path = tmp_path / "independent-controlled-validator-transcript.json"
    transcript_path.write_text(json.dumps(_sample_validator_transcript(), indent=2, sort_keys=True), encoding="utf-8")
    validate = _run(
        sys.executable,
        "scripts/validate_external_operator_transcript_v1_5.py",
        "--kind",
        "public_validator_operator_transcript",
        "--strict-release",
        "--path",
        str(transcript_path),
    )
    assert validate.returncode == 0, validate.stdout + validate.stderr


def test_public_beta_and_release_artifacts_reference_independent_validator_capture() -> None:
    for script in (
        "gen_release_evidence_manifest_v1_5.py",
        "gen_public_beta_blocker_report_v1_5.py",
    ):
        proc = _run(sys.executable, f"scripts/{script}", "--check")
        assert proc.returncode == 0, proc.stdout + proc.stderr

    report = json.loads((ROOT / "generated" / "public_beta_blocker_report_v1_5.json").read_text(encoding="utf-8"))
    blockers = {row["id"]: row for row in report["blockers"]}
    blocker = blockers["AUD-618-P0-001"]
    assert blocker["gate_status"] == "gate_present_external_attestation_required"
    assert blocker["can_be_closed_by_code_only"] is False
    assert "operator-signed transcript" in blocker["remaining_external_evidence"]
    assert report["public_beta_ready"] is False

    manifest = json.loads((ROOT / "generated" / "release_evidence_manifest_v1_5.json").read_text(encoding="utf-8"))
    gate = manifest["release_evidence_gates"]["external_validator_operator_transcript"]
    assert gate["blocker"] == "AUD-618-P0-001"
    assert gate["required_before_public_beta"] is True
    assert gate["required_before_controlled_validator_rehearsal_claim"] is True
    assert "capture_independent_controlled_validator_operator_transcript_v1_5.sh" in gate["capture_script"]
