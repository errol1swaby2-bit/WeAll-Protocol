from __future__ import annotations

import json
from types import SimpleNamespace

from public_seed_test_helpers import REGISTRY_PUBKEY, signed_endpoint, signed_registry
from weall.net.net_loop import NetMeshLoop


def _registry():
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
    data["validator_endpoints"] = [
        signed_endpoint(data, {"account_id": "@validator1", "api_base_url": "http://127.0.0.1:8001", "p2p_url": "tcp://127.0.0.1:30304"}),
        {"account_id": "@hint", "api_base_url": "http://127.0.0.1:8002", "p2p_url": "tcp://127.0.0.1:30305"},
    ]
    return signed_registry(data)


class _FakeExecutor(SimpleNamespace):
    chain_id = "weall-testnet-v1"

    def read_state(self):
        return {"chain_id": "weall-testnet-v1", "height": 0}


def test_net_loop_merges_public_registry_seed_and_verified_validator_peers(tmp_path, monkeypatch):
    registry_path = tmp_path / "public_seed_registry.json"
    peers_path = tmp_path / "peers.json"
    registry_path.write_text(json.dumps(_registry()), encoding="utf-8")

    monkeypatch.setenv("WEALL_MODE", "test")
    monkeypatch.setenv("WEALL_PUBLIC_TESTNET", "1")
    monkeypatch.setenv("WEALL_PUBLIC_TESTNET_ALLOW_LOCAL", "1")
    monkeypatch.setenv("WEALL_PUBLIC_TESTNET_SEED_REGISTRY_PATH", str(registry_path))
    monkeypatch.setenv("WEALL_PUBLIC_TESTNET_SEED_REGISTRY_PUBKEY", REGISTRY_PUBKEY)
    monkeypatch.setenv("WEALL_PEERS_FILE", str(peers_path))
    monkeypatch.setenv("WEALL_NET_ENABLED", "0")

    loop = NetMeshLoop(executor=_FakeExecutor(mempool=None), mempool=None)
    peers = loop._peers_store.read_list()
    assert "tcp://127.0.0.1:30303" in peers
    assert "tcp://127.0.0.1:30304" in peers
    assert "tcp://127.0.0.1:30305" not in peers
