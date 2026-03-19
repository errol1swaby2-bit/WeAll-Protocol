from __future__ import annotations

import importlib

import pytest



def test_tcp_transport_prod_rejects_invalid_connection_cap_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("WEALL_MODE", "prod")
    monkeypatch.setenv("WEALL_NET_MAX_CONNECTIONS", "bogus")

    import weall.net.transport_tcp as transport_tcp

    transport_tcp = importlib.reload(transport_tcp)
    with pytest.raises(ValueError, match="invalid_integer_env:WEALL_NET_MAX_CONNECTIONS"):
        transport_tcp.TcpTransport()



def test_tcp_transport_dev_defaults_invalid_connection_cap_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("WEALL_MODE", "dev")
    monkeypatch.setenv("WEALL_NET_MAX_CONNECTIONS", "bogus")

    import weall.net.transport_tcp as transport_tcp

    transport_tcp = importlib.reload(transport_tcp)
    tx = transport_tcp.TcpTransport()
    assert tx.max_connections_total == 200



def test_tls_transport_prod_rejects_invalid_connection_cap_env(monkeypatch: pytest.MonkeyPatch, tmp_path) -> None:
    monkeypatch.setenv("WEALL_MODE", "prod")
    monkeypatch.setenv("WEALL_NET_MAX_CONNECTIONS", "bogus")

    import weall.net.transport_tls as transport_tls

    transport_tls = importlib.reload(transport_tls)
    cert = tmp_path / "cert.pem"
    key = tmp_path / "key.pem"
    cert.write_text("cert", encoding="utf-8")
    key.write_text("key", encoding="utf-8")
    with pytest.raises(ValueError, match="invalid_integer_env:WEALL_NET_MAX_CONNECTIONS"):
        transport_tls.TlsTransport(server_cert=str(cert), server_key=str(key))



def test_state_sync_prod_rejects_invalid_integer_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("WEALL_MODE", "prod")
    monkeypatch.setenv("WEALL_SYNC_MAX_DELTA_BLOCKS", "bad")

    import weall.net.state_sync as state_sync

    state_sync = importlib.reload(state_sync)
    with pytest.raises(state_sync.StateSyncVerifyError, match="invalid_integer_env:WEALL_SYNC_MAX_DELTA_BLOCKS"):
        state_sync.StateSyncService(
            chain_id="weall",
            schema_version="1",
            tx_index_hash="abc",
            state_provider=lambda: {"height": 0},
        )



def test_state_sync_prod_rejects_invalid_boolean_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("WEALL_MODE", "prod")
    monkeypatch.setenv("WEALL_SYNC_REQUIRE_HEADER_MATCH", "maybe")

    import weall.net.state_sync as state_sync

    state_sync = importlib.reload(state_sync)
    with pytest.raises(state_sync.StateSyncVerifyError, match="invalid_boolean_env:WEALL_SYNC_REQUIRE_HEADER_MATCH"):
        state_sync.StateSyncService(
            chain_id="weall",
            schema_version="1",
            tx_index_hash="abc",
            state_provider=lambda: {"height": 0},
        )



def test_state_sync_dev_defaults_invalid_boolean_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("WEALL_MODE", "dev")
    monkeypatch.setenv("WEALL_SYNC_REQUIRE_HEADER_MATCH", "maybe")

    import weall.net.state_sync as state_sync

    state_sync = importlib.reload(state_sync)
    svc = state_sync.StateSyncService(
        chain_id="weall",
        schema_version="1",
        tx_index_hash="abc",
        state_provider=lambda: {"height": 0},
    )
    assert svc.require_header_match is True



def test_net_node_prod_rejects_invalid_explicit_transport_kind(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("WEALL_MODE", "prod")
    monkeypatch.setenv("WEALL_NET_TRANSPORT", "carrier-pigeon")

    import weall.net.node as node_mod

    node_mod = importlib.reload(node_mod)
    cfg = node_mod.NetConfig(chain_id="weall", schema_version="1", tx_index_hash="abc")
    with pytest.raises(RuntimeError, match="invalid_net_transport"):
        node_mod._make_transport(cfg)



def test_net_node_dev_defaults_invalid_explicit_transport_kind(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("WEALL_MODE", "dev")
    monkeypatch.setenv("WEALL_NET_TRANSPORT", "carrier-pigeon")

    import weall.net.node as node_mod

    node_mod = importlib.reload(node_mod)
    cfg = node_mod.NetConfig(chain_id="weall", schema_version="1", tx_index_hash="abc")
    transport = node_mod._make_transport(cfg)
    assert transport.__class__.__name__ == "InMemoryTransport"
