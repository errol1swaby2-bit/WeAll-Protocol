from __future__ import annotations

import json

from fastapi.testclient import TestClient

from public_seed_test_helpers import REGISTRY_PUBKEY, signed_registry
from weall.api.app import create_app
from weall.api.public_seed_registry import public_seed_registry_default_path


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
    }
    data.update(overrides)
    return data


def _public_env(monkeypatch) -> None:
    monkeypatch.setenv("WEALL_MODE", "test")
    monkeypatch.setenv("WEALL_API_MODE", "dev")
    monkeypatch.setenv("WEALL_PUBLIC_TESTNET", "1")
    monkeypatch.setenv("WEALL_PUBLIC_TESTNET_ALLOW_LOCAL", "1")
    monkeypatch.setenv("WEALL_PUBLIC_TESTNET_SEED_REGISTRY_PUBKEY", REGISTRY_PUBKEY)
    monkeypatch.delenv("WEALL_PUBLIC_TESTNET_SEED_REGISTRY_PATH", raising=False)
    monkeypatch.delenv("WEALL_PUBLIC_SEED_REGISTRY_PATH", raising=False)
    monkeypatch.delenv("WEALL_PUBLIC_TESTNET_DEFAULT_SEED_REGISTRY_PATH", raising=False)


def test_public_seed_registry_default_path_finds_configs_directory_from_outer_root(tmp_path, monkeypatch):
    registry_dir = tmp_path / "Weall-Protocol" / "configs"
    registry_dir.mkdir(parents=True)
    registry_path = registry_dir / "public_testnet_seed_registry.json"
    registry_path.write_text(json.dumps(signed_registry(_registry())), encoding="utf-8")

    monkeypatch.chdir(tmp_path)
    _public_env(monkeypatch)

    assert public_seed_registry_default_path() == str(registry_path)
    app = create_app(boot_runtime=False)
    r = TestClient(app).get("/v1/nodes/seeds")
    assert r.status_code == 200
    assert r.json()["seed_registry_signature_status"]["verified"] is True


def test_public_seed_registry_default_path_finds_configs_directory_from_backend_root(tmp_path, monkeypatch):
    registry_dir = tmp_path / "configs"
    registry_dir.mkdir(parents=True)
    registry_path = registry_dir / "public_testnet_seed_registry.json"
    registry_path.write_text(json.dumps(signed_registry(_registry())), encoding="utf-8")

    monkeypatch.chdir(tmp_path)
    _public_env(monkeypatch)

    assert public_seed_registry_default_path() == str(registry_path)
    app = create_app(boot_runtime=False)
    r = TestClient(app).get("/v1/nodes/seeds")
    assert r.status_code == 200
    assert r.json()["chain_id"] == "weall-testnet-v1"


def test_public_seed_registry_rejects_placeholder_launch_values(tmp_path, monkeypatch):
    data = signed_registry(_registry(genesis_hash="<set-before-public-launch>"))
    path = tmp_path / "public_testnet_seed_registry.json"
    path.write_text(json.dumps(data), encoding="utf-8")

    monkeypatch.setenv("WEALL_MODE", "prod")
    monkeypatch.setenv("WEALL_API_MODE", "node")
    monkeypatch.setenv("WEALL_PUBLIC_TESTNET", "1")
    monkeypatch.setenv("WEALL_PUBLIC_TESTNET_ALLOW_LOCAL", "1")
    monkeypatch.setenv("WEALL_PUBLIC_TESTNET_SEED_REGISTRY_PATH", str(path))
    monkeypatch.setenv("WEALL_PUBLIC_TESTNET_SEED_REGISTRY_PUBKEY", REGISTRY_PUBKEY)

    app = create_app(boot_runtime=False)
    r = TestClient(app).get("/v1/nodes/seeds")
    assert r.status_code == 503
    assert r.json()["error"]["code"] == "public_seed_registry_placeholder_genesis_hash"
