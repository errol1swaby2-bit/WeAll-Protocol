from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

from weall.runtime.block_admission import _get_active_validators_from_state
from weall.runtime.executor_boot import _verify_tx_index_artifact_only

ROOT = Path(__file__).resolve().parents[1]
VERIFY = ROOT / "scripts" / "verify_node_operator_onboarding_bundle.py"


def _manifest(path: Path, *, profile_hash: str = "3" * 64) -> Path:
    path.write_text(
        json.dumps(
            {
                "authority": {"expected_profile": "production"},
                "authority_snapshot_version": 1,
                "chain_id": "weall-prod-batch348",
                "genesis_hash": "1" * 64,
                "genesis_state_root": "2" * 64,
                "mode": "prod",
                "profile": "production_service",
                "protocol_profile_hash": profile_hash,
                "schema_version": "1",
                "trusted_authority_pubkeys": ["4" * 64],
                "tx_index_hash": "5" * 64,
                "version": 1,
            },
            sort_keys=True,
        ),
        encoding="utf-8",
    )
    return path


def _bundle(path: Path, *, profile_hash: str = "3" * 64) -> Path:
    path.write_text(
        json.dumps(
            {
                "type": "weall_node_operator_onboarding_bundle",
                "bundle_purpose": "external_observer_onboarding",
                "version": 1,
                "profile": "production",
                "chain": {
                    "chain_id": "weall-prod-batch348",
                    "genesis_hash": "1" * 64,
                    "genesis_state_root": "2" * 64,
                    "protocol_profile_hash": profile_hash,
                    "schema_version": "1",
                    "tx_index_hash": "5" * 64,
                },
                "authority": {
                    "profile": "production",
                    "authority_url": "https://authority.example.test",
                    "trusted_authority_pubkeys": ["4" * 64],
                },
                "observer": {
                    "observer_mode_required": True,
                    "node_lifecycle_state": "observer_onboarding",
                    "service_roles": [],
                    "validator_signing_enabled": False,
                    "bft_enabled": False,
                    "helper_authority_enabled": False,
                    "block_loop_autostart": False,
                    "allowed_onboarding_transactions": ["ACCOUNT_REGISTER", "PEER_ADVERTISE", "POH_ASYNC_REQUEST_OPEN"],
                },
            },
            sort_keys=True,
        ),
        encoding="utf-8",
    )
    return path


def test_observer_bundle_verifier_rejects_protocol_profile_hash_mismatch_batch348(tmp_path: Path) -> None:
    manifest = _manifest(tmp_path / "manifest.json", profile_hash="a" * 64)
    bundle = _bundle(tmp_path / "bundle.json", profile_hash="b" * 64)

    proc = subprocess.run(
        [sys.executable, str(VERIFY), "--bundle", str(bundle), "--manifest", str(manifest), "--json"],
        cwd=ROOT,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )

    assert proc.returncode != 0
    result = json.loads(proc.stdout)
    assert "manifest_protocol_profile_hash_mismatch" in result["issues"]


def test_verifier_exports_expected_protocol_profile_hash_batch348(tmp_path: Path) -> None:
    manifest = _manifest(tmp_path / "manifest.json", profile_hash="a" * 64)
    bundle = _bundle(tmp_path / "bundle.json", profile_hash="a" * 64)

    proc = subprocess.run(
        [sys.executable, str(VERIFY), "--bundle", str(bundle), "--manifest", str(manifest), "--emit-shell-env"],
        cwd=ROOT,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )

    assert proc.returncode == 0, proc.stderr + proc.stdout
    assert "export WEALL_EXPECTED_PROTOCOL_PROFILE_HASH=" + "a" * 64 in proc.stdout


def test_promoted_validator_scripts_use_bft_minimum_and_stable_validator_set_hash_batch348() -> None:
    preflight = (ROOT / "scripts" / "promoted_validator_preflight.sh").read_text(encoding="utf-8")
    live = (ROOT / "scripts" / "promoted_validator_live_gate.sh").read_text(encoding="utf-8")
    assert "BFT_MIN_VALIDATORS" in preflight
    assert "WEALL_PROMOTED_VALIDATOR_MIN_ACTIVE_VALIDATORS:-}" in preflight
    assert "current_validator_set_hash" in preflight
    assert "startup_fingerprint" in preflight
    assert "minimum_active_validators_required" in preflight
    assert "WEALL_PROMOTED_VALIDATOR_MIN_ACTIVE_VALIDATORS:-}" in live
    assert "active_validator_count_below_required" in live
    assert "consensus_peer_identity_verification_missing" in live


def test_consensus_validator_set_is_authoritative_over_role_active_set_batch348() -> None:
    state = {
        "roles": {"validators": {"active_set": ["role-only"]}},
        "consensus": {"validator_set": {"active_set": ["consensus-only"], "set_hash": "hash", "epoch": 1}},
    }
    assert _get_active_validators_from_state(state) == ["consensus-only"]


def test_production_tx_canon_verify_only_rejects_missing_or_stale_artifact_batch348(tmp_path: Path) -> None:
    missing = tmp_path / "missing-tx-index.json"
    with pytest.raises(RuntimeError, match="production tx canon artifact missing"):
        _verify_tx_index_artifact_only(str(missing))

    stale = tmp_path / "tx-index.json"
    stale.write_text(json.dumps({"source_sha256": "wrong", "tx_types": [{"name": "ACCOUNT_REGISTER"}], "by_name": {"ACCOUNT_REGISTER": 0}}), encoding="utf-8")
    with pytest.raises(RuntimeError, match="source_sha256 mismatch"):
        _verify_tx_index_artifact_only(str(stale))
