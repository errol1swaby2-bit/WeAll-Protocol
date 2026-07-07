from __future__ import annotations

import json

from fastapi.testclient import TestClient

from weall.api.app import create_app
from public_seed_test_helpers import REGISTRY_PUBKEY, signed_registry


def _registry(**overrides):
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
    }
    data.update(overrides)
    return data


def _public_env(monkeypatch, path=None):
    monkeypatch.setenv("WEALL_MODE", "test")
    monkeypatch.setenv("WEALL_API_MODE", "dev")
    monkeypatch.setenv("WEALL_PUBLIC_TESTNET", "1")
    monkeypatch.setenv("WEALL_PUBLIC_TESTNET_ALLOW_LOCAL", "1")
    if path is not None:
        monkeypatch.setenv("WEALL_PUBLIC_TESTNET_SEED_REGISTRY_PATH", str(path))
    monkeypatch.setenv("WEALL_PUBLIC_TESTNET_SEED_REGISTRY_PUBKEY", REGISTRY_PUBKEY)


def test_public_mode_missing_seed_registry_fails_closed(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    _public_env(monkeypatch)
    app = create_app(boot_runtime=False)
    r = TestClient(app).get("/v1/nodes/seeds")
    assert r.status_code == 503
    assert r.json()["error"]["code"] == "public_seed_registry_path_missing"


def test_public_mode_empty_seed_registry_fails_closed(tmp_path, monkeypatch):
    path = tmp_path / "public_seed_registry.json"
    path.write_text(json.dumps(signed_registry(_registry(seed_api_urls=[]))), encoding="utf-8")
    _public_env(monkeypatch, path)
    app = create_app(boot_runtime=False)
    r = TestClient(app).get("/v1/nodes/seeds")
    assert r.status_code == 503
    assert r.json()["error"]["code"] == "public_seed_registry_no_seed_api_urls"


def test_public_mode_rejects_insecure_non_local_public_seed(tmp_path, monkeypatch):
    path = tmp_path / "public_seed_registry.json"
    path.write_text(json.dumps(signed_registry(_registry(seed_api_urls=["http://evil.example.com"]))), encoding="utf-8")
    monkeypatch.setenv("WEALL_MODE", "prod")
    monkeypatch.setenv("WEALL_API_MODE", "prod")
    monkeypatch.setenv("WEALL_PUBLIC_TESTNET", "1")
    monkeypatch.setenv("WEALL_PUBLIC_TESTNET_SEED_REGISTRY_PATH", str(path))
    monkeypatch.setenv("WEALL_PUBLIC_TESTNET_SEED_REGISTRY_PUBKEY", REGISTRY_PUBKEY)
    app = create_app(boot_runtime=False)
    r = TestClient(app).get("/v1/nodes/seeds")
    assert r.status_code == 503
    assert r.json()["error"]["code"] == "public_seed_registry_invalid_seed_api_url"


def test_public_mode_valid_seed_registry_returns_commitments(tmp_path, monkeypatch):
    path = tmp_path / "public_seed_registry.json"
    path.write_text(json.dumps(signed_registry(_registry())), encoding="utf-8")
    _public_env(monkeypatch, path)
    app = create_app(boot_runtime=False)
    r = TestClient(app).get("/v1/nodes/seeds")
    assert r.status_code == 200
    j = r.json()
    assert j["ok"] is True
    assert j["public_testnet"] is True
    assert j["chain_id"] == "weall-testnet-v1"
    assert j["genesis_hash"] == "genesis-hash-test"
    assert j["protocol_profile_hash"] == "profile-hash-test"
    assert j["tx_index_hash"] == "tx-index-hash-test"
    assert j["resettable_testnet"] is True
    assert j["economics_active"] is False
    assert j["nodes"][0]["base_url"] == "http://127.0.0.1:8000"


def test_local_dev_seed_registry_still_works_without_public_mode(tmp_path, monkeypatch):
    path = tmp_path / "nodes_registry.json"
    path.write_text(json.dumps({"version": 3, "nodes": [{"base_url": "http://127.0.0.1:8000"}]}), encoding="utf-8")
    monkeypatch.setenv("WEALL_MODE", "test")
    monkeypatch.setenv("WEALL_API_MODE", "dev")
    monkeypatch.setenv("WEALL_ALLOW_INSECURE_LOCALHOST", "1")
    monkeypatch.setenv("WEALL_NODES_REGISTRY_PATH", str(path))
    app = create_app(boot_runtime=False)
    r = TestClient(app).get("/v1/nodes/seeds")
    assert r.status_code == 200
    j = r.json()
    assert j["ok"] is True
    assert j["version"] == 3
    assert j["nodes"][0]["base_url"] == "http://127.0.0.1:8000"


def test_public_seed_registry_rejects_bad_signature(tmp_path, monkeypatch):
    data = signed_registry(_registry())
    data["genesis_hash"] = "tampered-after-signature"
    path = tmp_path / "public_seed_registry.json"
    path.write_text(json.dumps(data), encoding="utf-8")
    _public_env(monkeypatch, path)
    monkeypatch.setenv("WEALL_PUBLIC_TESTNET_REQUIRE_SIGNATURES", "1")
    app = create_app(boot_runtime=False)
    r = TestClient(app).get("/v1/nodes/seeds")
    assert r.status_code == 503
    assert r.json()["error"]["code"] == "public_seed_registry_bad_signature"


def test_public_seed_registry_rejects_unsupported_p2p_scheme(tmp_path, monkeypatch):
    path = tmp_path / "public_seed_registry.json"
    path.write_text(json.dumps(signed_registry(_registry(seed_p2p_urls=["p2p://127.0.0.1:30303"]))), encoding="utf-8")
    _public_env(monkeypatch, path)
    app = create_app(boot_runtime=False)
    r = TestClient(app).get("/v1/nodes/seeds")
    assert r.status_code == 503
    assert r.json()["error"]["code"] == "p2p_url_bad_scheme"
