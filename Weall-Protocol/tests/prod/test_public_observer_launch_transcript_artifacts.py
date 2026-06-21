from __future__ import annotations

import json
import os
import subprocess
import sys


ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))


def _run(*args: str) -> subprocess.CompletedProcess[str]:
    env = os.environ.copy()
    env.pop("PYTEST_CURRENT_TEST", None)
    env.setdefault("PYTHONDONTWRITEBYTECODE", "1")
    return subprocess.run(
        [sys.executable, *args],
        cwd=ROOT,
        env=env,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        timeout=45,
    )


def _load(rel: str) -> dict:
    with open(os.path.join(ROOT, rel), encoding="utf-8") as f:
        return json.load(f)


def test_public_observer_launch_transcript_static_artifacts_are_current_and_conservative() -> None:
    proc = _run("scripts/gen_public_observer_launch_transcript_v1_5.py", "--check")
    assert proc.returncode == 0, proc.stdout + proc.stderr
    for rel, schema in {
        "generated/public_seed_registry_signature_verification_v1_5.json": "weall.v1_5.public_seed_registry_signature_verification",
        "generated/public_observer_clean_clone_bootstrap_transcript_v1_5.json": "weall.v1_5.public_observer_clean_clone_bootstrap_transcript",
        "generated/public_observer_auto_discovery_proof_v1_5.json": "weall.v1_5.public_observer_auto_discovery_proof",
        "generated/public_observer_state_sync_trusted_anchor_proof_v1_5.json": "weall.v1_5.public_observer_state_sync_trusted_anchor_proof",
    }.items():
        payload = _load(rel)
        assert payload["schema"] == schema
        assert payload["ok"] is True
        assert payload["public_observer_launch_ready"] is False
        assert payload["external_evidence_required_before_launch"] is True


def test_public_validator_endpoint_churn_and_frontend_operator_artifacts_are_conservative() -> None:
    for rel, schema in [
        (
            "generated/public_validator_endpoint_churn_proof_v1_5.json",
            "weall.v1_5.public_validator_endpoint_churn_proof",
        ),
        (
            "generated/public_frontend_operator_journey_v1_5.json",
            "weall.v1_5.public_frontend_operator_journey",
        ),
        (
            "generated/public_registry_signer_operations_v1_5.json",
            "weall.v1_5.public_registry_signer_operations",
        ),
    ]:
        payload = _load(rel)
        assert payload["schema"] == schema
        assert payload["ok"] is True
        assert payload.get("public_observer_launch_ready") is False
        assert payload.get("artifact_digest")


def test_public_observer_runtime_transcript_missing_live_endpoints_does_not_create_launch_claim(tmp_path) -> None:
    out = tmp_path / "runtime.json"
    env = os.environ.copy()
    env["WEALL_PUBLIC_TESTNET"] = "1"
    env["WEALL_PUBLIC_TESTNET_SEED_REGISTRY_PUBKEY"] = "00" * 32
    proc = subprocess.run(
        [
            sys.executable,
            "scripts/gen_public_observer_launch_transcript_v1_5.py",
            "--runtime-json",
            "--api-base",
            "http://127.0.0.1:9",
            "--out",
            str(out),
        ],
        cwd=ROOT,
        env=env,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    assert proc.returncode != 0
    payload = json.loads(out.read_text(encoding="utf-8"))
    assert payload["schema"] == "weall.v1_5.public_observer_launch_runtime_transcript"
    assert payload["public_observer_launch_ready"] is False
    assert payload["endpoint_errors"]
