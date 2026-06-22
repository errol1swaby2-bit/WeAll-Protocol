from __future__ import annotations

import json
from types import SimpleNamespace

from fastapi.testclient import TestClient

import weall.api.public_seed_registry as public_seed_registry
from public_seed_test_helpers import REGISTRY_PUBKEY, signed_endpoint, signed_registry
from weall.api.app import create_app
from weall.net.gossip import make_peer_addr_record
from weall.net.messages import MsgType, PeerAddrMsg, WireHeader
from weall.net.net_loop import NetMeshLoop
from weall.net.node import NetConfig, NetNode


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
    monkeypatch.setenv("WEALL_API_MODE", "dev")
    monkeypatch.setenv("WEALL_PUBLIC_TESTNET", "1")
    monkeypatch.setenv("WEALL_PUBLIC_TESTNET_ALLOW_LOCAL", "1")
    monkeypatch.setenv("WEALL_PUBLIC_TESTNET_SEED_REGISTRY_PUBKEY", REGISTRY_PUBKEY)
    monkeypatch.delenv("WEALL_PUBLIC_TESTNET_SEED_REGISTRY_PATH", raising=False)
    monkeypatch.delenv("WEALL_PUBLIC_SEED_REGISTRY_PATH", raising=False)
    monkeypatch.delenv("WEALL_PUBLIC_TESTNET_DEFAULT_SEED_REGISTRY_PATH", raising=False)
    monkeypatch.delenv("WEALL_PUBLIC_TESTNET_SEED_REGISTRY_URL", raising=False)
    monkeypatch.delenv("WEALL_PUBLIC_TESTNET_SEED_REGISTRY_URLS", raising=False)
    monkeypatch.delenv("WEALL_PUBLIC_SEED_REGISTRY_URL", raising=False)
    monkeypatch.delenv("WEALL_PUBLIC_SEED_REGISTRY_URLS", raising=False)
    monkeypatch.delenv("WEALL_PUBLIC_TESTNET_TRUST_ROOTS_PATH", raising=False)
    monkeypatch.delenv("WEALL_PUBLIC_TESTNET_DEFAULT_TRUST_ROOTS_PATH", raising=False)


class _FakeExecutor(SimpleNamespace):
    chain_id = "weall-testnet-v1"

    def read_state(self):
        return {"chain_id": "weall-testnet-v1", "height": 0}


class _DummyMempool:
    pass


def _header(kind: MsgType) -> WireHeader:
    return WireHeader(type=kind, chain_id="weall-testnet-v1", schema_version="1", tx_index_hash="tx-index-hash-test")




def test_repo_shipped_trust_roots_can_supply_remote_url_and_signer_pin(tmp_path, monkeypatch):
    _public_env(monkeypatch)
    monkeypatch.delenv("WEALL_PUBLIC_TESTNET_SEED_REGISTRY_PUBKEY", raising=False)
    roots_dir = tmp_path / "Weall-Protocol" / "configs"
    roots_dir.mkdir(parents=True)
    trust_roots_path = roots_dir / "public_testnet_trust_roots.json"
    trust_roots_path.write_text(
        json.dumps(
            {
                "version": 1,
                "seed_registry_pubkeys": [REGISTRY_PUBKEY],
                "seed_registry_urls": ["http://127.0.0.1:9999/registry.json"],
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("WEALL_PUBLIC_TESTNET_USE_DEFAULT_TRUST_ROOTS", "1")
    remote = signed_registry(_registry(seed_p2p_urls=["tcp://127.0.0.1:30344"]))
    monkeypatch.setattr(public_seed_registry, "_http_get_registry_json", lambda _url, *, timeout_s: remote)

    registry = public_seed_registry.load_public_seed_registry()

    assert registry["seed_registry_signature_status"]["trust"] == "pinned"
    assert registry["registry_source_kind"] == "remote_url"
    assert registry["seed_p2p_urls"] == ["tcp://127.0.0.1:30344"]


def test_remote_signed_seed_registry_url_is_a_valid_hybrid_source(monkeypatch):
    _public_env(monkeypatch)
    monkeypatch.setenv("WEALL_PUBLIC_TESTNET_SEED_REGISTRY_URL", "http://127.0.0.1:9999/public_testnet_seed_registry.json")
    remote = signed_registry(_registry(seed_p2p_urls=["tcp://127.0.0.1:30333"]))

    def fake_fetch(url: str, *, timeout_s: float):
        assert url == "http://127.0.0.1:9999/public_testnet_seed_registry.json"
        assert timeout_s > 0
        return remote

    monkeypatch.setattr(public_seed_registry, "_http_get_registry_json", fake_fetch)

    app = create_app(boot_runtime=False)
    r = TestClient(app).get("/v1/nodes/seeds")

    assert r.status_code == 200, r.text
    j = r.json()
    assert j["seed_registry_signature_status"]["verified"] is True
    assert j["registry_source_kind"] == "remote_url"
    assert j["registry_source"] == "http://127.0.0.1:9999/public_testnet_seed_registry.json"
    assert j["seed_p2p_urls"] == ["tcp://127.0.0.1:30333"]


def test_hybrid_registry_falls_back_to_checked_in_default_when_remote_unreachable(tmp_path, monkeypatch):
    _public_env(monkeypatch)
    monkeypatch.setenv("WEALL_PUBLIC_TESTNET_SEED_REGISTRY_URL", "http://127.0.0.1:9999/missing.json")
    registry_dir = tmp_path / "Weall-Protocol" / "configs"
    registry_dir.mkdir(parents=True)
    registry_path = registry_dir / "public_testnet_seed_registry.json"
    registry_path.write_text(json.dumps(signed_registry(_registry(chain_id="weall-testnet-fallback"))), encoding="utf-8")
    monkeypatch.chdir(tmp_path)

    def fake_fetch(_url: str, *, timeout_s: float):
        raise public_seed_registry.PublicSeedRegistryError("public_seed_registry_remote_fetch_failed")

    monkeypatch.setattr(public_seed_registry, "_http_get_registry_json", fake_fetch)

    registry = public_seed_registry.load_public_seed_registry()

    assert registry["chain_id"] == "weall-testnet-fallback"
    assert registry["registry_source_kind"] == "file"
    assert registry["registry_source"] == str(registry_path)


def test_net_loop_merges_remote_registry_peers_and_keeps_learned_peer_file(tmp_path, monkeypatch):
    _public_env(monkeypatch)
    monkeypatch.setenv("WEALL_PUBLIC_TESTNET_SEED_REGISTRY_URL", "http://127.0.0.1:9999/public_testnet_seed_registry.json")
    monkeypatch.setenv("WEALL_PEERS_FILE", str(tmp_path / "peers.txt"))
    monkeypatch.setenv("WEALL_NET_ENABLED", "0")
    remote = _registry(seed_p2p_urls=["tcp://127.0.0.1:30303"])
    remote["validator_endpoints"] = [
        signed_endpoint(remote, {"account_id": "@validator1", "api_base_url": "http://127.0.0.1:8001", "p2p_url": "tcp://127.0.0.1:30304"}),
        {"account_id": "@hint", "api_base_url": "http://127.0.0.1:8002", "p2p_url": "tcp://127.0.0.1:30305"},
    ]
    remote = signed_registry(remote)
    monkeypatch.setattr(public_seed_registry, "_http_get_registry_json", lambda _url, *, timeout_s: remote)

    loop = NetMeshLoop(executor=_FakeExecutor(mempool=None), mempool=_DummyMempool())
    peers = loop._peers_store.read_list()

    assert "tcp://127.0.0.1:30303" in peers
    assert "tcp://127.0.0.1:30304" in peers
    assert "tcp://127.0.0.1:30305" not in peers


def test_public_mode_peer_addr_gossip_requires_signed_records(monkeypatch):
    _public_env(monkeypatch)
    accepted: list[tuple[str, tuple[dict, ...]]] = []
    node = NetNode(
        cfg=NetConfig(
            chain_id="weall-testnet-v1",
            schema_version="1",
            tx_index_hash="tx-index-hash-test",
            peer_id="local",
        ),
        on_peer_addr_records=lambda peer_id, records: accepted.append((peer_id, tuple(records))),
    )
    node._ensure_peer("peer-x")
    unsigned = make_peer_addr_record(
        uri="tcp://unsigned.example:30303",
        peer_id="unsigned",
        chain_id="weall-testnet-v1",
        schema_version="1",
        tx_index_hash="tx-index-hash-test",
    )
    signed = make_peer_addr_record(
        uri="tcp://signed.example:30303",
        peer_id="signed",
        chain_id="weall-testnet-v1",
        schema_version="1",
        tx_index_hash="tx-index-hash-test",
        pubkey=REGISTRY_PUBKEY,
        privkey="11" * 32,
    )

    node._handle_peer_addr("peer-x", PeerAddrMsg(header=_header(MsgType.PEER_ADDR), addrs=(unsigned, signed)))

    assert accepted == [("peer-x", (signed,))]
    peer = {p["peer_id"]: p for p in node.peers_debug()["peers"]}["peer-x"]
    assert peer["addr_records_received"] == 2
    assert peer["addr_records_accepted"] == 1
    assert peer["addr_records_rejected"] == 1
