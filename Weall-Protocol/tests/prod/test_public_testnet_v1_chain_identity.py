from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

from public_seed_test_helpers import REGISTRY_PUBKEY, signed_registry
from weall.api.public_seed_registry import PublicSeedRegistryError, load_public_seed_registry
from weall.runtime.chain_manifest import load_chain_manifest
from weall.runtime.state_hash import compute_state_root

ROOT = Path(__file__).resolve().parents[2]


def test_public_testnet_v1_chain_identity_is_pinned_and_deterministic() -> None:
    manifest_path = ROOT / "configs" / "chains" / "weall-testnet-v1.json"
    ledger_path = ROOT / "configs" / "genesis.ledger.testnet-v1.json"
    commitments_path = ROOT / "configs" / "public_testnet_chain_commitments.json"

    manifest = load_chain_manifest(str(manifest_path), required=True)
    ledger = json.loads(ledger_path.read_text(encoding="utf-8"))
    commitments = json.loads(commitments_path.read_text(encoding="utf-8"))

    assert manifest.chain_id == "weall-testnet-v1"
    assert manifest.raw["network_id"] == "weall-public-observer-testnet-v1"
    assert manifest.raw["resettable_testnet"] is True
    assert ledger["chain_id"] == manifest.chain_id
    assert ledger["params"]["economics_enabled"] is False
    assert ledger["params"]["public_mainnet_enabled"] is False
    assert ledger["params"]["public_testnet_v1"] is True
    assert ledger["params"]["resettable_testnet"] is True
    assert compute_state_root(ledger) == manifest.genesis_state_root

    assert commitments["network_id"] == manifest.raw["network_id"]
    assert commitments["chain_id"] == manifest.chain_id
    assert commitments["genesis_hash"] == manifest.genesis_hash
    assert commitments["genesis_state_root"] == manifest.genesis_state_root
    assert commitments["protocol_profile_hash"] == manifest.protocol_profile_hash
    assert commitments["tx_index_hash"] == manifest.tx_index_hash
    assert commitments["resettable_testnet"] is True
    assert commitments["economics_active"] is False


def test_public_testnet_v1_chain_identity_generator_is_fresh() -> None:
    result = subprocess.run(
        [
            sys.executable,
            str(ROOT / "scripts" / "gen_public_testnet_v1_chain_identity.py"),
            "--check",
        ],
        cwd=ROOT,
        env={"PYTHONPATH": str(ROOT / "src")},
        text=True,
        capture_output=True,
        check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr


def test_checked_in_registry_and_trust_roots_match_current_public_testnet_identity(monkeypatch) -> None:
    manifest = json.loads((ROOT / "configs" / "chains" / "weall-testnet-v1.json").read_text(encoding="utf-8"))
    commitments = json.loads((ROOT / "configs" / "public_testnet_chain_commitments.json").read_text(encoding="utf-8"))
    trust_roots_path = ROOT / "configs" / "public_testnet_trust_roots.json"
    registry_path = ROOT / "configs" / "public_testnet_seed_registry.json"
    trust_roots = json.loads(trust_roots_path.read_text(encoding="utf-8"))
    registry = json.loads(registry_path.read_text(encoding="utf-8"))

    expected = {
        "network_id": manifest["network_id"],
        "chain_id": manifest["chain_id"],
        "genesis_hash": manifest["genesis_hash"],
        "protocol_profile_hash": manifest["protocol_profile_hash"],
        "tx_index_hash": manifest["tx_index_hash"],
    }
    for key, value in expected.items():
        assert commitments[key] == value
        assert trust_roots[key] == value
        assert registry[key] == value

    monkeypatch.setenv("WEALL_MODE", "prod")
    monkeypatch.setenv("WEALL_PUBLIC_TESTNET", "1")
    monkeypatch.setenv("WEALL_PUBLIC_TESTNET_TRUST_ROOTS_PATH", str(trust_roots_path))
    monkeypatch.setenv("WEALL_PUBLIC_TESTNET_SEED_REGISTRY_PATH", str(registry_path))
    monkeypatch.delenv("WEALL_PUBLIC_TESTNET_SEED_REGISTRY_PUBKEY", raising=False)
    monkeypatch.delenv("WEALL_PUBLIC_TESTNET_SEED_REGISTRY_PUBKEYS", raising=False)
    monkeypatch.delenv("WEALL_EXPECTED_TX_INDEX_HASH", raising=False)

    loaded = load_public_seed_registry(allow_local=False)

    assert loaded["tx_index_hash"] == manifest["tx_index_hash"]
    assert loaded["seed_registry_signature_status"]["verified"] is True
    assert loaded["seed_registry_signature_status"]["trust"] == "pinned"
    assert loaded["provider_authority"] is False


def test_public_registry_is_rejected_when_it_does_not_match_repo_trust_roots(tmp_path, monkeypatch) -> None:
    trust_roots = tmp_path / "public_testnet_trust_roots.json"
    trust_roots.write_text(
        json.dumps(
            {
                "version": 1,
                "network_id": "weall-public-observer-testnet-v1",
                "chain_id": "weall-testnet-v1",
                "genesis_hash": "expected-genesis-hash",
                "protocol_profile_hash": "expected-profile-hash",
                "tx_index_hash": "expected-tx-index-hash",
                "seed_registry_pubkeys": [REGISTRY_PUBKEY],
            }
        ),
        encoding="utf-8",
    )
    registry = tmp_path / "public_testnet_seed_registry.json"
    registry.write_text(
        json.dumps(
            signed_registry(
                {
                    "version": 1,
                    "network_id": "weall-public-observer-testnet-v1",
                    "chain_id": "weall-testnet-v1",
                    "genesis_hash": "wrong-genesis-hash",
                    "protocol_profile_hash": "expected-profile-hash",
                    "tx_index_hash": "expected-tx-index-hash",
                    "seed_api_urls": ["http://127.0.0.1:8000"],
                    "seed_p2p_urls": ["tcp://127.0.0.1:30303"],
                    "active_validator_endpoint_policy": "verified_or_hint",
                    "resettable_testnet": True,
                    "economics_active": False,
                    "validator_endpoints": [],
                }
            )
        ),
        encoding="utf-8",
    )
    monkeypatch.setenv("WEALL_MODE", "test")
    monkeypatch.setenv("WEALL_PUBLIC_TESTNET", "1")
    monkeypatch.setenv("WEALL_PUBLIC_TESTNET_ALLOW_LOCAL", "1")
    monkeypatch.setenv("WEALL_PUBLIC_TESTNET_TRUST_ROOTS_PATH", str(trust_roots))
    monkeypatch.setenv("WEALL_PUBLIC_TESTNET_SEED_REGISTRY_PATH", str(registry))
    monkeypatch.delenv("WEALL_PUBLIC_TESTNET_SEED_REGISTRY_PUBKEY", raising=False)

    with pytest.raises(PublicSeedRegistryError, match="public_seed_registry_genesis_hash_mismatch"):
        load_public_seed_registry()


def test_public_registry_matching_repo_trust_roots_is_accepted(tmp_path, monkeypatch) -> None:
    manifest = json.loads((ROOT / "configs" / "chains" / "weall-testnet-v1.json").read_text(encoding="utf-8"))
    trust_roots = tmp_path / "public_testnet_trust_roots.json"
    trust_roots.write_text(
        json.dumps(
            {
                "version": 1,
                "network_id": manifest["network_id"],
                "chain_id": manifest["chain_id"],
                "genesis_hash": manifest["genesis_hash"],
                "protocol_profile_hash": manifest["protocol_profile_hash"],
                "tx_index_hash": manifest["tx_index_hash"],
                "seed_registry_pubkeys": [REGISTRY_PUBKEY],
            }
        ),
        encoding="utf-8",
    )
    registry = tmp_path / "public_testnet_seed_registry.json"
    registry.write_text(
        json.dumps(
            signed_registry(
                {
                    "version": 1,
                    "network_id": manifest["network_id"],
                    "chain_id": manifest["chain_id"],
                    "genesis_hash": manifest["genesis_hash"],
                    "protocol_profile_hash": manifest["protocol_profile_hash"],
                    "tx_index_hash": manifest["tx_index_hash"],
                    "seed_api_urls": ["http://127.0.0.1:8000"],
                    "seed_p2p_urls": ["tcp://127.0.0.1:30303"],
                    "active_validator_endpoint_policy": "verified_or_hint",
                    "resettable_testnet": True,
                    "economics_active": False,
                    "validator_endpoints": [],
                }
            )
        ),
        encoding="utf-8",
    )
    monkeypatch.setenv("WEALL_MODE", "test")
    monkeypatch.setenv("WEALL_PUBLIC_TESTNET", "1")
    monkeypatch.setenv("WEALL_PUBLIC_TESTNET_ALLOW_LOCAL", "1")
    monkeypatch.setenv("WEALL_PUBLIC_TESTNET_TRUST_ROOTS_PATH", str(trust_roots))
    monkeypatch.setenv("WEALL_PUBLIC_TESTNET_SEED_REGISTRY_PATH", str(registry))
    monkeypatch.delenv("WEALL_PUBLIC_TESTNET_SEED_REGISTRY_PUBKEY", raising=False)

    loaded = load_public_seed_registry()

    assert loaded["chain_id"] == "weall-testnet-v1"
    assert loaded["genesis_hash"] == manifest["genesis_hash"]
    assert loaded["seed_registry_signature_status"]["verified"] is True
