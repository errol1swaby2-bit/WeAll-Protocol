from __future__ import annotations

from fastapi.testclient import TestClient

from weall.api.app import create_app
from weall.net.net_loop import NetLoopConfig, NetMeshLoop


class _DummyExecutor:
    chain_id = "weall-testnet-v1"

    def read_state(self):
        return {"chain_id": "weall-testnet-v1", "height": 0, "accounts": {}}

    def tx_index_hash(self) -> str:
        return "tx-index-hash-test"

    def _schema_version(self) -> str:
        return "1"


class _DummyMempool:
    def peek(self, _n: int):
        return []


def _client(monkeypatch) -> TestClient:
    monkeypatch.setenv("WEALL_MODE", "test")
    monkeypatch.setenv("WEALL_API_MODE", "dev")
    monkeypatch.setenv("WEALL_NET_REQUIRE_PEER_IDENTITY", "0")
    app = create_app(boot_runtime=False)
    app.state.executor = _DummyExecutor()
    return TestClient(app)


def test_public_observer_nat_status_warns_without_advertise_or_relay(monkeypatch) -> None:
    monkeypatch.setenv("WEALL_PUBLIC_TESTNET", "1")
    monkeypatch.setenv("WEALL_NET_BIND_HOST", "0.0.0.0")
    monkeypatch.delenv("WEALL_NET_ADVERTISE_URI", raising=False)
    monkeypatch.delenv("WEALL_NET_RELAY_CLIENT_ENABLED", raising=False)

    r = _client(monkeypatch).get("/v1/net/self")

    assert r.status_code == 200, r.text
    body = r.json()
    nat = body["nat"]
    assert nat["public_testnet"] is True
    assert nat["recommended_profile"] == "needs_advertise_or_relay"
    assert nat["inbound_reachable_claim"] is False
    assert "public_testnet_no_public_advertise_or_relay" in nat["warnings"]
    assert "public_testnet_no_public_advertise_or_relay" in body["warnings"]
    assert nat["authority"] == "network_transport_only"


def test_public_observer_nat_status_accepts_relay_only_profile(monkeypatch) -> None:
    monkeypatch.setenv("WEALL_PUBLIC_TESTNET", "1")
    monkeypatch.setenv("WEALL_NET_NAT_MODE", "relay_only")
    monkeypatch.setenv("WEALL_NET_RELAY_CLIENT_ENABLED", "1")
    monkeypatch.setenv("WEALL_NET_RELAY_URLS", "https://relay.weall.example")
    monkeypatch.setenv("WEALL_NET_RELAY_RECIPIENTS", "genesis")
    monkeypatch.setenv("WEALL_NET_RELAY_RECIPIENT_PUBKEYS", '{"genesis":"' + "a" * 64 + '"}')

    r = _client(monkeypatch).get("/v1/net/self")

    assert r.status_code == 200, r.text
    nat = r.json()["nat"]
    assert nat["mode"] == "relay_only"
    assert nat["recommended_profile"] == "relay_only"
    assert nat["relay"]["client_enabled"] is True
    assert nat["relay"]["client_ready"] is True
    assert nat["relay"]["authority"] == "transport_only"
    assert "public_testnet_no_public_advertise_or_relay" not in nat["warnings"]


def test_validator_or_seed_nat_requires_public_advertise_uri(monkeypatch) -> None:
    monkeypatch.setenv("WEALL_PUBLIC_TESTNET", "1")
    monkeypatch.setenv("WEALL_VALIDATOR_SIGNING_ENABLED", "1")
    monkeypatch.setenv("WEALL_NET_ADVERTISE_URI", "tcp://127.0.0.1:30303")

    r = _client(monkeypatch).get("/v1/net/self")

    assert r.status_code == 200, r.text
    nat = r.json()["nat"]
    assert nat["inbound_required"] is True
    assert nat["advertise"]["status"] == "loopback"
    assert "inbound_required_without_public_advertise_uri" in nat["warnings"]
    assert "advertise_uri_not_public:loopback" in nat["warnings"]


def test_public_advertise_uri_sets_inbound_reachable_claim(monkeypatch) -> None:
    monkeypatch.setenv("WEALL_PUBLIC_TESTNET", "1")
    monkeypatch.setenv("WEALL_NET_ADVERTISE_URI", "tls://seed.weall.example:30303")

    r = _client(monkeypatch).get("/v1/net/self")

    assert r.status_code == 200, r.text
    nat = r.json()["nat"]
    assert nat["advertise"]["host_kind"] == "dns"
    assert nat["advertise"]["status"] == "public_or_dns"
    assert nat["inbound_reachable_claim"] is True
    assert nat["recommended_profile"] == "public_inbound"


def test_seed_discovery_debug_exposes_periodic_refresh_state(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("WEALL_MODE", "test")
    monkeypatch.setenv("WEALL_PUBLIC_TESTNET", "0")
    monkeypatch.setenv("WEALL_PEERS_FILE", str(tmp_path / "peers.txt"))
    monkeypatch.setenv("WEALL_SEED_NODES", "http://seed-a.example")
    monkeypatch.setenv("WEALL_SEED_DISCOVERY_REFRESH_MS", "250")

    loop = NetMeshLoop(
        executor=_DummyExecutor(),
        mempool=_DummyMempool(),
        cfg=NetLoopConfig(enabled=False, bind_host="127.0.0.1", bind_port=30303, tick_ms=25, schema_version="1"),
    )

    dbg = loop.seed_discovery_debug()
    assert dbg["seed_nodes_configured"] == 1
    assert dbg["refresh_ms"] == 250
    assert dbg["last_ok"] is False
