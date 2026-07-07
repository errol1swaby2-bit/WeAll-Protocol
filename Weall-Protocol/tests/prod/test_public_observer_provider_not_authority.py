from __future__ import annotations

import json

from fastapi.testclient import TestClient

import weall.api.public_seed_registry as public_seed_registry
from public_seed_test_helpers import REGISTRY_PUBKEY, signed_registry
from weall.api.app import create_app


def test_nodes_seeds_reports_provider_authority_false_for_generic_mirror(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("WEALL_MODE", "prod")
    monkeypatch.setenv("WEALL_API_MODE", "node")
    monkeypatch.setenv("WEALL_PUBLIC_TESTNET", "1")
    monkeypatch.setenv("WEALL_PUBLIC_TESTNET_SEED_REGISTRY_PUBKEY", REGISTRY_PUBKEY)
    roots = tmp_path / "roots.json"
    roots.write_text(
        json.dumps(
            {
                "version": 1,
                "network_id": "weall-public-observer-testnet-v1",
                "chain_id": "weall-testnet-v1",
                "genesis_hash": "genesis-hash-test",
                "protocol_profile_hash": "profile-hash-test",
                "tx_index_hash": "tx-index-hash-test",
                "seed_registry_pubkeys": [REGISTRY_PUBKEY],
                "seed_registry_mirrors": [{"url": "https://mirror.example.org/registry.json", "provider": "custom"}],
                "seed_registry_urls": [],
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setenv("WEALL_PUBLIC_TESTNET_TRUST_ROOTS_PATH", str(roots))
    for key in ("WEALL_PUBLIC_TESTNET_SEED_REGISTRY_PATH", "WEALL_PUBLIC_TESTNET_DEFAULT_SEED_REGISTRY_PATH"):
        monkeypatch.delenv(key, raising=False)
    registry = signed_registry(
        {
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
    )
    monkeypatch.setattr(public_seed_registry, "_http_get_registry_json", lambda _url, *, timeout_s: registry)

    response = TestClient(create_app(boot_runtime=False)).get("/v1/nodes/seeds")

    assert response.status_code == 200, response.text
    data = response.json()
    assert data["registry_source_provider"] == "generic_https"
    assert data["provider_authority"] is False
    assert data["registry_mirror_attempts"][-1]["accepted"] is True
