from __future__ import annotations

import json

import weall.api.public_seed_registry as public_seed_registry
from public_seed_test_helpers import REGISTRY_PUBKEY, signed_registry


def _registry(**overrides) -> dict:
    data = {
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
    data.update(overrides)
    return data


def _public_env(monkeypatch) -> None:
    monkeypatch.setenv("WEALL_MODE", "test")
    monkeypatch.setenv("WEALL_PUBLIC_TESTNET", "1")
    monkeypatch.setenv("WEALL_PUBLIC_TESTNET_ALLOW_LOCAL", "1")
    monkeypatch.setenv("WEALL_PUBLIC_TESTNET_SEED_REGISTRY_PUBKEY", REGISTRY_PUBKEY)
    for key in (
        "WEALL_PUBLIC_TESTNET_SEED_REGISTRY_PATH",
        "WEALL_PUBLIC_SEED_REGISTRY_PATH",
        "WEALL_PUBLIC_TESTNET_DEFAULT_SEED_REGISTRY_PATH",
        "WEALL_PUBLIC_TESTNET_SEED_REGISTRY_URL",
        "WEALL_PUBLIC_TESTNET_SEED_REGISTRY_URLS",
        "WEALL_PUBLIC_SEED_REGISTRY_URL",
        "WEALL_PUBLIC_SEED_REGISTRY_URLS",
        "WEALL_PUBLIC_TESTNET_TRUST_ROOTS_PATH",
        "WEALL_PUBLIC_TESTNET_DEFAULT_TRUST_ROOTS_PATH",
    ):
        monkeypatch.delenv(key, raising=False)


def test_checked_in_signed_registry_bootstraps_without_remote_url(tmp_path, monkeypatch) -> None:
    _public_env(monkeypatch)
    registry_dir = tmp_path / "Weall-Protocol" / "configs"
    registry_dir.mkdir(parents=True)
    registry_path = registry_dir / "public_testnet_seed_registry.json"
    registry_path.write_text(json.dumps(signed_registry(_registry())), encoding="utf-8")
    roots_path = registry_dir / "public_testnet_trust_roots.json"
    roots_path.write_text(
        json.dumps(
            {
                "version": 1,
                "network_id": "weall-public-observer-testnet-v1",
                "chain_id": "weall-testnet-v1",
                "genesis_hash": "genesis-hash-test",
                "protocol_profile_hash": "profile-hash-test",
                "tx_index_hash": "tx-index-hash-test",
                "seed_registry_pubkeys": [REGISTRY_PUBKEY],
                "seed_registry_mirrors": [],
                "seed_registry_urls": [],
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("WEALL_PUBLIC_TESTNET_USE_DEFAULT_TRUST_ROOTS", "1")

    registry = public_seed_registry.load_public_seed_registry()

    assert registry["registry_source_kind"] == "file"
    assert registry["registry_source_provider"] == "local_file"
    assert registry["provider_authority"] is False
    assert registry["seed_registry_signature_status"]["verified"] is True
    assert registry["seed_p2p_urls"] == ["tcp://127.0.0.1:30303"]
    assert registry["registry_mirror_attempts"][-1]["accepted"] is True
