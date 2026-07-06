from __future__ import annotations

import json
import os
import subprocess
import sys

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.mldsa import MLDSA65PrivateKey

from public_seed_test_helpers import REGISTRY_PUBKEY


def _registry() -> dict:
    return {
        "version": 1,
        "network_id": "weall-public-observer-testnet-v1",
        "chain_id": "weall-testnet-v1",
        "genesis_hash": "genesis-hash-test",
        "protocol_profile_hash": "profile-hash-test",
        "tx_index_hash": "tx-index-hash-test",
        "seed_api_urls": ["http://127.0.0.1:8000"],
        "seed_p2p_urls": ["tcp://127.0.0.1:30303"],
        "active_validator_endpoint_policy": "verified_or_hint",
        "resettable_testnet": True,
        "economics_active": False,
        "validator_endpoints": [],
    }


def test_public_seed_registry_signing_script_rejects_placeholders_and_writes_valid_registry(tmp_path):
    root = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
    privkey = "11" * 32
    input_path = tmp_path / "unsigned.json"
    output_path = tmp_path / "public_testnet_seed_registry.json"
    input_path.write_text(json.dumps(_registry()), encoding="utf-8")

    env = os.environ.copy()
    env["WEALL_PUBLIC_TESTNET_SEED_REGISTRY_PRIVKEY"] = privkey
    env["WEALL_PUBLIC_TESTNET_SEED_REGISTRY_PUBKEY"] = REGISTRY_PUBKEY
    env["WEALL_MODE"] = "test"
    proc = subprocess.run(
        [
            sys.executable,
            "scripts/sign_public_seed_registry_v1_5.py",
            "--input",
            str(input_path),
            "--output",
            str(output_path),
            "--registry-public-key",
            REGISTRY_PUBKEY,
            "--signature-profile",
            "classical-signature-profile-removed",
            "--allow-local",
        ],
        cwd=root,
        env=env,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
    signed = json.loads(output_path.read_text(encoding="utf-8"))
    assert signed["seed_registry_signer"] == REGISTRY_PUBKEY
    assert signed["seed_registry_signature"]

    check = subprocess.run(
        [
            sys.executable,
            "scripts/sign_public_seed_registry_v1_5.py",
            "--input",
            str(input_path),
            "--output",
            str(output_path),
            "--registry-public-key",
            REGISTRY_PUBKEY,
            "--signature-profile",
            "classical-signature-profile-removed",
            "--allow-local",
            "--check",
        ],
        cwd=root,
        env=env,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    assert check.returncode == 0, check.stdout + check.stderr


def test_public_observer_boot_script_is_fail_closed_and_documents_recovery():
    root = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
    script = os.path.join(root, "scripts", "boot_public_observer_testnet.sh")
    assert os.path.exists(script)
    assert os.access(script, os.X_OK)
    text = open(script, encoding="utf-8").read()
    assert "WEALL_PUBLIC_TESTNET_SEED_REGISTRY_PUBKEY" in text
    assert "public_testnet_seed_registry.json" in text
    assert "/v1/nodes/seeds" in text
    assert "/v1/nodes/validators" in text
    assert "/v1/observer/edge/status" in text
    assert "/v1/net/self" in text
    assert "WEALL_NET_ENABLED" in text
    assert "WEALL_NET_LOOP_AUTOSTART" in text
    assert "WEALL_VALIDATOR_SIGNING_ENABLED" in text
    assert "init_prod_node_identity.sh --emit-shell-env" in text
    assert "exec bash scripts/run_node.sh" in text
    assert "exec python3 -m weall.api" not in text


def test_public_observer_launch_evidence_requirements_generator_check():
    root = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
    result = subprocess.run(
        [sys.executable, "scripts/gen_public_observer_launch_evidence_requirements_v1_5.py", "--json"],
        cwd=root,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    payload = json.loads(result.stdout)
    assert payload["schema"] == "weall.v1_5.public_observer_launch_evidence_requirements"
    assert payload["public_observer_launch_ready"] is False
    assert payload["required_gate_count"] >= 5
    gate_ids = {gate["id"] for gate in payload["gates"]}
    assert "clean_clone_public_observer_boot" in gate_ids
    assert "validator_endpoint_churn_visibility" in gate_ids
    assert "tracked_launch_transcript_artifacts" in gate_ids
    assert "registry_signer_rotation_and_revocation" in gate_ids
