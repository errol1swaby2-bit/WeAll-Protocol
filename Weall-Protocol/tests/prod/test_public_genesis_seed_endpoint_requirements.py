from __future__ import annotations

import copy

import pytest

from public_seed_test_helpers import REGISTRY_PUBKEY, signed_endpoint, signed_registry
from weall.api.public_seed_registry import PublicSeedRegistryError, normalize_public_seed_registry


def _base_registry() -> dict:
    return {
        "version": 1,
        "network_id": "weall-public-observer-testnet-v1",
        "chain_id": "weall-testnet-v1",
        "genesis_hash": "genesis-hash-test",
        "protocol_profile_hash": "profile-hash-test",
        "tx_index_hash": "tx-index-hash-test",
        "seed_api_urls": ["https://api.genesis.weallprotocol.xyz"],
        "seed_p2p_urls": ["tls://p2p.genesis.weallprotocol.xyz:30303"],
        "active_validator_endpoint_policy": "verified_or_hint",
        "resettable_testnet": True,
        "economics_active": False,
        "validator_endpoints": [],
    }


def _set_public_registry_env(monkeypatch) -> None:
    monkeypatch.setenv("WEALL_PUBLIC_TESTNET", "1")
    monkeypatch.setenv("WEALL_MODE", "prod")
    monkeypatch.setenv("WEALL_PUBLIC_TESTNET_SEED_REGISTRY_PUBKEY", REGISTRY_PUBKEY)
    base = _base_registry()
    monkeypatch.setenv("WEALL_PUBLIC_TESTNET_NETWORK_ID", base["network_id"])
    monkeypatch.setenv("WEALL_EXPECTED_CHAIN_ID", base["chain_id"])
    monkeypatch.setenv("WEALL_EXPECTED_GENESIS_HASH", base["genesis_hash"])
    monkeypatch.setenv("WEALL_EXPECTED_PROTOCOL_PROFILE_HASH", base["protocol_profile_hash"])
    monkeypatch.setenv("WEALL_EXPECTED_TX_INDEX_HASH", base["tx_index_hash"])


def _assert_registry_rejected(monkeypatch, registry: dict, code: str) -> None:
    _set_public_registry_env(monkeypatch)
    signed = signed_registry(registry)
    with pytest.raises(PublicSeedRegistryError) as excinfo:
        normalize_public_seed_registry(signed, allow_local=False)
    assert str(excinfo.value) == code


def test_public_genesis_registry_requires_direct_p2p_seed(monkeypatch):
    registry = _base_registry()
    registry["seed_p2p_urls"] = []
    _assert_registry_rejected(monkeypatch, registry, "public_seed_registry_no_seed_p2p_urls")


@pytest.mark.parametrize(
    ("api_url", "code"),
    [
        ("https://127.0.0.1:8443", "public_seed_registry_seed_api_url_not_public"),
        ("https://10.0.0.2", "public_seed_registry_seed_api_url_not_public"),
        ("https://[::1]:8443", "public_seed_registry_seed_api_url_not_public"),
    ],
)
def test_public_genesis_registry_rejects_private_or_loopback_seed_api(monkeypatch, api_url: str, code: str):
    registry = _base_registry()
    registry["seed_api_urls"] = [api_url]
    _assert_registry_rejected(monkeypatch, registry, code)


@pytest.mark.parametrize(
    ("p2p_url", "code"),
    [
        ("tcp://127.0.0.1:30303", "public_seed_registry_seed_p2p_url_not_public"),
        ("tls://10.0.0.2:30303", "public_seed_registry_seed_p2p_url_not_public"),
        ("tls://[::1]:30303", "public_seed_registry_seed_p2p_url_not_public"),
    ],
)
def test_public_genesis_registry_rejects_private_or_loopback_seed_p2p(monkeypatch, p2p_url: str, code: str):
    registry = _base_registry()
    registry["seed_p2p_urls"] = [p2p_url]
    _assert_registry_rejected(monkeypatch, registry, code)


def test_public_genesis_registry_accepts_public_dns_seed_endpoints(monkeypatch):
    _set_public_registry_env(monkeypatch)
    out = normalize_public_seed_registry(signed_registry(_base_registry()), allow_local=False)
    assert out["seed_api_urls"] == ["https://api.genesis.weallprotocol.xyz"]
    assert out["seed_p2p_urls"] == ["tls://p2p.genesis.weallprotocol.xyz:30303"]


def test_public_validator_endpoint_hints_must_not_advertise_private_public_launch_addresses(monkeypatch):
    registry = _base_registry()
    registry["validator_endpoints"] = [
        signed_endpoint(
            registry,
            {
                "account_id": "validator-a",
                "api_base_url": "https://10.0.0.9:8443",
                "p2p_url": "tls://validator-a.weallprotocol.xyz:30303",
                "endpoint_source": "public_seed_registry",
            },
        )
    ]
    _assert_registry_rejected(monkeypatch, registry, "public_validator_endpoint_api_base_url_not_public")


def test_public_validator_endpoint_hints_must_not_advertise_private_p2p_addresses(monkeypatch):
    registry = _base_registry()
    registry["validator_endpoints"] = [
        signed_endpoint(
            registry,
            {
                "account_id": "validator-a",
                "api_base_url": "https://validator-a.weallprotocol.xyz",
                "p2p_url": "tcp://127.0.0.1:30303",
                "endpoint_source": "public_seed_registry",
            },
        )
    ]
    _assert_registry_rejected(monkeypatch, registry, "public_validator_endpoint_p2p_url_not_public")
