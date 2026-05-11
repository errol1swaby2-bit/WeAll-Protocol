from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
BUILD = ROOT / "scripts" / "build_external_observer_bundle.py"
VERIFY = ROOT / "scripts" / "verify_node_operator_onboarding_bundle.py"


def _manifest(path: Path) -> Path:
    obj = {
        "authority": {
            "authority_snapshot_required": True,
            "expected_profile": "production",
            "signed_snapshot_required": True,
        },
        "authority_snapshot_version": 1,
        "chain_id": "weall-prod-observer-secret-boundary",
        "genesis_hash": "1" * 64,
        "genesis_state_root": "2" * 64,
        "mode": "prod",
        "profile": "production_service",
        "protocol_profile_hash": "3" * 64,
        "schema_version": "1",
        "trusted_authority_pubkeys": ["4" * 64],
        "tx_index_hash": "5" * 64,
        "version": 1,
    }
    path.write_text(json.dumps(obj, sort_keys=True), encoding="utf-8")
    return path


def test_observer_bundle_contains_no_authority_secrets(tmp_path: Path) -> None:
    manifest = _manifest(tmp_path / "manifest.json")
    bundle = tmp_path / "observer-bundle.json"
    result = subprocess.run(
        [
            sys.executable,
            str(BUILD),
            "--manifest",
            str(manifest),
            "--genesis-api-base",
            "https://genesis.example.test",
            "--relay-urls",
            "https://relay.example.test",
            "--genesis-recipient-pubkey",
            "a" * 64,
            "--out",
            str(bundle),
            "--generated-at-ms",
            "1900000000000",
        ],
        cwd=str(ROOT),
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    assert result.returncode == 0, result.stderr + result.stdout

    verified = subprocess.run(
        [
            sys.executable,
            str(VERIFY),
            "--bundle",
            str(bundle),
            "--manifest",
            str(manifest),
            "--json",
        ],
        cwd=str(ROOT),
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    assert verified.returncode == 0, verified.stderr + verified.stdout
    assert json.loads(verified.stdout)["ok"] is True

    data = json.loads(bundle.read_text(encoding="utf-8"))
    dumped = json.dumps(data, sort_keys=True).lower()
    forbidden_values = [
        "genesis-private",
        "authority-private",
        "validator-private",
        "cloudflare-token",
        "smtp-password",
        "email-oracle-secret",
    ]
    for value in forbidden_values:
        assert value not in dumped

    prohibited = data["secret_boundary"]["prohibited_environment_variables"]
    assert "WEALL_NODE_PRIVKEY" in prohibited
    assert "WEALL_AUTHORITY_SIGNER_PRIVKEY" in prohibited
    assert "WEALL_AUTHORITY_PRIVKEY" in prohibited
    assert "WEALL_CLOUDFLARE_API_TOKEN" in prohibited
    assert data["observer"]["validator_signing_enabled"] is False
    assert data["observer"]["bft_enabled"] is False
    assert data["operator_requirements"]["no_genesis_authority_material_required"] is True
    assert data["operator_requirements"]["no_external_identity_provider_required"] is True
