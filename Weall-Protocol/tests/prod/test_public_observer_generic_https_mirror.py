from __future__ import annotations

import json

import pytest

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
        "seed_api_urls": ["https://seed.example.org"],
        "seed_p2p_urls": ["tls://seed.example.org:30303"],
        "active_validator_endpoint_policy": "verified_or_hint",
        "resettable_testnet": True,
        "economics_active": False,
        "validator_endpoints": [],
    }
    data.update(overrides)
    return data


def _public_env(monkeypatch) -> None:
    monkeypatch.setenv("WEALL_MODE", "prod")
    monkeypatch.setenv("WEALL_PUBLIC_TESTNET", "1")
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


def _trust_roots(tmp_path, mirrors) -> str:
    path = tmp_path / "trust_roots.json"
    path.write_text(
        json.dumps(
            {
                "version": 1,
                "network_id": "weall-public-observer-testnet-v1",
                "chain_id": "weall-testnet-v1",
                "genesis_hash": "genesis-hash-test",
                "protocol_profile_hash": "profile-hash-test",
                "tx_index_hash": "tx-index-hash-test",
                "seed_registry_pubkeys": [REGISTRY_PUBKEY],
                "seed_registry_mirrors": mirrors,
                "seed_registry_urls": [],
            }
        ),
        encoding="utf-8",
    )
    return str(path)


def test_generic_https_mirror_is_accepted_without_provider_specific_logic(tmp_path, monkeypatch) -> None:
    _public_env(monkeypatch)
    monkeypatch.setenv("WEALL_PUBLIC_TESTNET_TRUST_ROOTS_PATH", _trust_roots(tmp_path, [{"url": "https://mirror.example.org/public_testnet_seed_registry.json", "provider": "anything"}]))
    remote = signed_registry(_registry(seed_p2p_urls=["tls://mirror-seed.example.org:30303"]))
    monkeypatch.setattr(public_seed_registry, "_http_get_registry_json", lambda _url, *, timeout_s: remote)

    registry = public_seed_registry.load_public_seed_registry()

    assert registry["registry_source_kind"] == "remote_url"
    assert registry["registry_source_provider"] == "generic_https"
    assert registry["provider_authority"] is False
    assert registry["seed_p2p_urls"] == ["tls://mirror-seed.example.org:30303"]


def test_bad_generic_mirror_falls_back_to_checked_in_registry(tmp_path, monkeypatch) -> None:
    _public_env(monkeypatch)
    monkeypatch.setenv("WEALL_PUBLIC_TESTNET_TRUST_ROOTS_PATH", _trust_roots(tmp_path, ["https://mirror.example.org/bad.json"]))
    registry_dir = tmp_path / "Weall-Protocol" / "configs"
    registry_dir.mkdir(parents=True)
    fallback = registry_dir / "public_testnet_seed_registry.json"
    fallback.write_text(json.dumps(signed_registry(_registry(seed_p2p_urls=["tls://fallback.example.org:30303"]))), encoding="utf-8")
    monkeypatch.chdir(tmp_path)

    def bad_fetch(_url: str, *, timeout_s: float):
        broken = signed_registry(_registry(chain_id="wrong-chain"))
        return broken

    monkeypatch.setattr(public_seed_registry, "_http_get_registry_json", bad_fetch)

    registry = public_seed_registry.load_public_seed_registry()

    assert registry["registry_source_kind"] == "file"
    assert registry["seed_p2p_urls"] == ["tls://fallback.example.org:30303"]
    assert registry["registry_mirror_attempts"][0]["accepted"] is False
    assert registry["registry_mirror_attempts"][-1]["accepted"] is True


def test_wrong_signature_is_rejected_even_if_mirror_metadata_claims_authority(tmp_path, monkeypatch) -> None:
    _public_env(monkeypatch)
    monkeypatch.setenv("WEALL_PUBLIC_TESTNET_TRUST_ROOTS_PATH", _trust_roots(tmp_path, [{"url": "https://mirror.example.org/registry.json", "provider": "trusted", "authority": True}]))
    bad = signed_registry(_registry())
    bad["seed_registry_signature"] = "00" * 64
    monkeypatch.setattr(public_seed_registry, "_http_get_registry_json", lambda _url, *, timeout_s: bad)

    with pytest.raises(public_seed_registry.PublicSeedRegistryError):
        public_seed_registry.load_public_seed_registry()
