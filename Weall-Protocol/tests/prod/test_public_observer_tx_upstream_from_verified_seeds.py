from __future__ import annotations

import json
from types import SimpleNamespace

from weall.api.routes_public_parts.tx import _normalized_tx_upstream_urls, _propagate_tx_to_configured_upstreams
from public_seed_test_helpers import REGISTRY_PUBKEY, signed_endpoint, signed_registry


def _request(path):
    cfg = SimpleNamespace(public_seed_registry_path=str(path))
    return SimpleNamespace(app=SimpleNamespace(state=SimpleNamespace(cfg=cfg)), headers={})


def _registry(validator_endpoints):
    data = {
        "version": 1,
        "network_id": "weall-public-observer-testnet-v1",
        "chain_id": "weall-testnet-v1",
        "genesis_hash": "genesis-hash-test",
        "protocol_profile_hash": "profile-hash-test",
        "tx_index_hash": "tx-index-hash-test",
        "seed_api_urls": ["http://127.0.0.1:8000"],
        "seed_p2p_urls": ["tcp://127.0.0.1:30303"],
        "resettable_testnet": True,
        "economics_active": False,
        "validator_endpoints": validator_endpoints,
    }
    return signed_registry(data)


def _registry_with_signed_endpoint(endpoint):
    data = {
        "version": 1,
        "network_id": "weall-public-observer-testnet-v1",
        "chain_id": "weall-testnet-v1",
        "genesis_hash": "genesis-hash-test",
        "protocol_profile_hash": "profile-hash-test",
        "tx_index_hash": "tx-index-hash-test",
        "seed_api_urls": ["http://127.0.0.1:8000"],
        "seed_p2p_urls": ["tcp://127.0.0.1:30303"],
        "resettable_testnet": True,
        "economics_active": False,
        "validator_endpoints": [],
    }
    data["validator_endpoints"] = [signed_endpoint(data, endpoint)]
    return signed_registry(data)



def test_explicit_tx_upstream_still_wins(tmp_path, monkeypatch):
    path = tmp_path / "public_seed_registry.json"
    path.write_text(json.dumps(_registry([])), encoding="utf-8")
    monkeypatch.setenv("WEALL_MODE", "test")
    monkeypatch.setenv("WEALL_PUBLIC_TESTNET", "1")
    monkeypatch.setenv("WEALL_PUBLIC_TESTNET_ALLOW_LOCAL", "1")
    monkeypatch.setenv("WEALL_PUBLIC_TESTNET_SEED_REGISTRY_PUBKEY", REGISTRY_PUBKEY)
    monkeypatch.setenv("WEALL_TX_UPSTREAM_URLS", "https://explicit.example.com")
    assert _normalized_tx_upstream_urls(_request(path)) == ["https://explicit.example.com"]


def test_public_observer_derives_verified_upstreams_from_seed_registry(tmp_path, monkeypatch):
    path = tmp_path / "public_seed_registry.json"
    path.write_text(json.dumps(_registry_with_signed_endpoint({"account_id": "@v", "api_base_url": "http://127.0.0.1:8001"})), encoding="utf-8")
    monkeypatch.setenv("WEALL_MODE", "test")
    monkeypatch.setenv("WEALL_PUBLIC_TESTNET", "1")
    monkeypatch.setenv("WEALL_PUBLIC_TESTNET_ALLOW_LOCAL", "1")
    monkeypatch.setenv("WEALL_PUBLIC_TESTNET_SEED_REGISTRY_PUBKEY", REGISTRY_PUBKEY)
    assert _normalized_tx_upstream_urls(_request(path)) == ["http://127.0.0.1:8001", "http://127.0.0.1:8000"]


def test_no_verified_public_upstream_returns_clear_skip(tmp_path, monkeypatch):
    path = tmp_path / "public_seed_registry.json"
    path.write_text(json.dumps(_registry([])), encoding="utf-8")
    monkeypatch.setenv("WEALL_MODE", "test")
    monkeypatch.setenv("WEALL_PUBLIC_TESTNET", "1")
    monkeypatch.setenv("WEALL_PUBLIC_TESTNET_ALLOW_LOCAL", "1")
    monkeypatch.setenv("WEALL_PUBLIC_TESTNET_SEED_REGISTRY_PUBKEY", REGISTRY_PUBKEY)
    # Simulate an unusable seed registry by removing all seeds after schema validation path cannot load a tx target.
    monkeypatch.delenv("WEALL_TX_UPSTREAM_URLS", raising=False)
    result = _propagate_tx_to_configured_upstreams(_request(path), {"chain_id": "weall-testnet-v1"}, tx_id="tx1")
    # A seed URL exists, so propagation is attempted; no HTTP server is required to prove no false success.
    assert result["attempted"] is True
    assert result["accepted"] is False


def test_missing_public_registry_has_no_false_success(tmp_path, monkeypatch):
    missing = tmp_path / "missing.json"
    monkeypatch.setenv("WEALL_MODE", "test")
    monkeypatch.setenv("WEALL_PUBLIC_TESTNET", "1")
    monkeypatch.setenv("WEALL_PUBLIC_TESTNET_ALLOW_LOCAL", "1")
    monkeypatch.setenv("WEALL_PUBLIC_TESTNET_SEED_REGISTRY_PUBKEY", REGISTRY_PUBKEY)
    result = _propagate_tx_to_configured_upstreams(_request(missing), {"chain_id": "weall-testnet-v1"}, tx_id="tx1")
    assert result["attempted"] is False
    assert result["accepted"] is False
    assert result["error"] == "PUBLIC_TESTNET_NO_VERIFIED_TX_UPSTREAM"


def test_public_upstream_identity_requires_full_commitments(monkeypatch):
    from weall.api.routes_public_parts import tx as tx_routes

    monkeypatch.setenv("WEALL_MODE", "test")
    monkeypatch.setenv("WEALL_PUBLIC_TESTNET", "1")
    monkeypatch.setenv("WEALL_TX_UPSTREAM_REQUIRE_MANIFEST", "0")

    def fake_get_json(_url, path, *, timeout_s):
      assert path == "/v1/chain/identity"
      return {
          "chain_id": "weall-testnet-v1",
          "genesis_hash": "wrong-genesis",
          "tx_index_hash": "tx-index-hash-test",
          "protocol_profile_hash": "profile-hash-test",
      }

    monkeypatch.setattr(tx_routes, "_upstream_get_json", fake_get_json)
    result = tx_routes._verify_upstream_identity(
        "http://127.0.0.1:8001",
        expected_chain_id="weall-testnet-v1",
        timeout_s=1,
        expected_commitments={
            "chain_id": "weall-testnet-v1",
            "genesis_hash": "genesis-hash-test",
            "tx_index_hash": "tx-index-hash-test",
            "protocol_profile_hash": "profile-hash-test",
        },
    )
    assert result["ok"] is False
    assert result["error"] == "upstream_identity_genesis_hash_mismatch"
