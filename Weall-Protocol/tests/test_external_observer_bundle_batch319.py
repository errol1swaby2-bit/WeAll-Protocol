from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OBSERVER_SCRIPT = ROOT / "scripts" / "build_external_observer_bundle.py"
VERIFY_SCRIPT = ROOT / "scripts" / "verify_node_operator_onboarding_bundle.py"
SMOKE_SCRIPT = ROOT / "scripts" / "external_observer_onboarding_smoke.sh"
GENESIS_RECIPIENT_PUBKEY = "a" * 64


def _write_manifest(path: Path) -> Path:
    manifest = {
        "authority": {
            "authority_snapshot_required": True,
            "expected_profile": "production",
            "signed_snapshot_required": True,
        },
        "authority_snapshot_version": 1,
        "chain_id": "weall-prod-observer-test",
        "genesis_hash": "1" * 64,
        "genesis_state_root": "2" * 64,
        "mode": "prod",
        "profile": "production_service",
        "protocol_profile_hash": "3" * 64,
        "schema_version": "1",
        "trusted_authority_pubkeys": ["b" * 64],
        "tx_index_hash": "4" * 64,
        "version": 1,
    }
    path.write_text(json.dumps(manifest, sort_keys=True), encoding="utf-8")
    return path


def _build_observer_bundle(tmp_path: Path, *, relay_urls: str = "https://relay.example.test") -> tuple[Path, Path]:
    manifest = _write_manifest(tmp_path / "manifest.json")
    bundle = tmp_path / "observer-bundle.json"
    result = subprocess.run(
        [
            sys.executable,
            str(OBSERVER_SCRIPT),
            "--manifest",
            str(manifest),
            "--genesis-api-base",
            "https://genesis.example.test",
            "--relay-urls",
            relay_urls,
            "--genesis-recipient-pubkey",
            GENESIS_RECIPIENT_PUBKEY,
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
    return manifest, bundle


def test_external_observer_bundle_builder_outputs_public_observer_bundle_batch319(tmp_path: Path) -> None:
    _manifest, bundle = _build_observer_bundle(
        tmp_path,
        relay_urls="https://relay-a.example.test,https://relay-b.example.test",
    )

    data = json.loads(bundle.read_text(encoding="utf-8"))
    assert data["type"] == "weall_node_operator_onboarding_bundle"
    assert data["bundle_purpose"] == "external_observer_onboarding"
    assert data["chain"]["chain_id"] == "weall-prod-observer-test"
    assert data["observer"]["observer_mode_required"] is True
    assert data["observer"]["validator_signing_enabled"] is False
    assert data["observer"]["bft_enabled"] is False
    assert data["observer"]["helper_authority_enabled"] is False
    assert data["observer"]["block_loop_autostart"] is False
    assert data["observer"]["relay_urls"] == ["https://relay-a.example.test", "https://relay-b.example.test"]
    assert data["observer"]["relay_recipient_pubkeys"] == {"genesis": GENESIS_RECIPIENT_PUBKEY}
    assert data["observer"]["relay_recipients"] == ["genesis"]
    assert "ACCOUNT_REGISTER" in data["observer"]["allowed_onboarding_transactions"]
    assert "PEER_ADVERTISE" in data["observer"]["allowed_onboarding_transactions"]
    assert "POH_ASYNC_REQUEST_OPEN" in data["observer"]["allowed_onboarding_transactions"]
    dumped = json.dumps(data, sort_keys=True)
    assert "WEALL_NODE_PRIVKEY" in dumped  # listed only as a prohibited variable
    assert "WEALL_AUTHORITY_SIGNER_PRIVKEY" in dumped  # listed only as a prohibited variable
    assert "WEALL_CLOUDFLARE_API_TOKEN" in dumped  # listed only as a prohibited variable


def test_external_observer_bundle_verifies_and_exports_safe_observer_env_batch319(tmp_path: Path) -> None:
    manifest, bundle = _build_observer_bundle(tmp_path)

    verified = subprocess.run(
        [
            sys.executable,
            str(VERIFY_SCRIPT),
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
    result = json.loads(verified.stdout)
    assert result["ok"] is True
    assert result["trusted_authority_pubkeys_count"] == 1
    assert result["relay_recipient_pubkeys_count"] == 1

    env_result = subprocess.run(
        [
            sys.executable,
            str(VERIFY_SCRIPT),
            "--bundle",
            str(bundle),
            "--manifest",
            str(manifest),
            "--emit-shell-env",
        ],
        cwd=str(ROOT),
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    assert env_result.returncode == 0, env_result.stderr + env_result.stdout
    out = env_result.stdout
    assert "export WEALL_GENESIS_API_BASE=https://genesis.example.test" in out
    assert "export WEALL_NET_RELAY_URLS=https://relay.example.test" in out
    assert "export WEALL_NET_RELAY_RECIPIENT_PUBKEYS=" in out
    assert GENESIS_RECIPIENT_PUBKEY in out
    assert "export WEALL_NODE_LIFECYCLE_STATE=observer_onboarding" in out
    assert "export WEALL_OBSERVER_MODE=1" in out
    assert "export WEALL_VALIDATOR_SIGNING_ENABLED=0" in out
    assert "export WEALL_BFT_ENABLED=0" in out
    assert "export WEALL_HELPER_MODE_ENABLED=0" in out
    assert "export WEALL_BLOCK_LOOP_AUTOSTART=0" in out


def test_external_observer_smoke_consumes_bundle_genesis_api_env_batch319() -> None:
    script = SMOKE_SCRIPT.read_text(encoding="utf-8")
    assert "GENESIS_API_BASE=\"${GENESIS_API_BASE:-${WEALL_GENESIS_API_BASE:-}}\"" in script
    assert "WEALL_NET_RELAY_URLS" in script
    assert "WEALL_NET_RELAY_RECIPIENT_PUBKEYS" in script
    assert "require_recipient_pubkey" in script
    assert "allow_unbound_recipient_fetch" in script
    assert "transport_only" in script


def test_external_observer_rehearsal_runbook_documents_two_machine_gate_batch319() -> None:
    doc = (ROOT / "docs" / "EXTERNAL_OBSERVER_NODE_REHEARSAL.md").read_text(encoding="utf-8")
    assert "Machine A" in doc
    assert "Machine B" in doc
    assert "ACCOUNT_REGISTER" in doc
    assert "PEER_ADVERTISE" in doc
    assert "PEER_REQUEST_CONNECT" in doc
    assert "POH_ASYNC_REQUEST_OPEN" in doc
    assert "cannot propose blocks" in doc
    assert "cannot sign validator messages" in doc
    assert "transport_only" in doc
    assert "No email, Cloudflare, SMTP, DNS, OAuth, CAPTCHA, KYC" in doc
