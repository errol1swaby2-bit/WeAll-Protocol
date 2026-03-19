from __future__ import annotations

import json
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient

from weall.api.app import create_app


class _FakeSession(SimpleNamespace):
    pass


class _FakeNode:
    def __init__(self):
        self._peers = {"peer-a": _FakeSession(addr=SimpleNamespace(uri="tcp://1.2.3.4:5555"), established=True)}

    def peer_ids(self):
        raise RuntimeError("boom")


class _FakeExecutorBadSnapshot:
    def snapshot(self):
        raise RuntimeError("snapshot failed")


@pytest.mark.parametrize("path", ["/v1/nodes/seeds", "/v1/nodes"])
def test_nodes_seeds_invalid_env_fails_closed_in_prod(monkeypatch, path):
    monkeypatch.setenv("WEALL_MODE", "prod")
    monkeypatch.setenv("WEALL_SEED_NODES", "http://evil.example.com")
    app = create_app(boot_runtime=False)
    c = TestClient(app, raise_server_exceptions=True)
    with pytest.raises(Exception) as excinfo:
        c.get(path)
    assert "seed_nodes_invalid_base_url" in str(excinfo.value)


def test_nodes_seeds_invalid_env_stays_permissive_in_dev(monkeypatch):
    monkeypatch.setenv("WEALL_MODE", "dev")
    monkeypatch.setenv("WEALL_SEED_NODES", "http://evil.example.com,https://good.example.com")
    app = create_app(boot_runtime=False)
    c = TestClient(app)
    r = c.get("/v1/nodes/seeds")
    assert r.status_code == 200
    urls = [n["base_url"] for n in r.json()["nodes"]]
    assert urls == ["https://good.example.com"]


def test_nodes_registry_bad_weight_fails_closed_in_prod(tmp_path, monkeypatch):
    reg_path = tmp_path / "nodes_registry.json"
    reg_path.write_text(json.dumps({"version": 1, "nodes": [{"base_url": "https://alpha.example.com", "weight": "nope"}]}), encoding="utf-8")
    monkeypatch.setenv("WEALL_MODE", "prod")
    monkeypatch.setenv("WEALL_NODES_REGISTRY_PATH", str(reg_path))
    app = create_app(boot_runtime=False)
    c = TestClient(app, raise_server_exceptions=True)
    with pytest.raises(Exception) as excinfo:
        c.get("/v1/nodes/seeds")
    assert "registry_node_bad_weight" in str(excinfo.value)


def test_nodes_known_peer_ids_failure_fails_closed_in_prod(monkeypatch):
    monkeypatch.setenv("WEALL_MODE", "prod")
    app = create_app(boot_runtime=False)
    app.state.net_node = _FakeNode()
    c = TestClient(app, raise_server_exceptions=True)
    with pytest.raises(Exception) as excinfo:
        c.get("/v1/nodes/known")
    assert "nodes_known_peer_ids_failed" in str(excinfo.value)


def test_net_self_invalid_bind_port_fails_closed_in_prod(monkeypatch):
    monkeypatch.setenv("WEALL_MODE", "prod")
    monkeypatch.setenv("WEALL_NET_BIND_PORT", "nope")
    app = create_app(boot_runtime=False)
    c = TestClient(app, raise_server_exceptions=True)
    with pytest.raises(Exception) as excinfo:
        c.get("/v1/net/self")
    assert "invalid_integer_env:WEALL_NET_BIND_PORT" in str(excinfo.value)


def test_net_self_snapshot_failure_fails_closed_in_prod(monkeypatch):
    monkeypatch.setenv("WEALL_MODE", "prod")
    app = create_app(boot_runtime=False)
    app.state.executor = _FakeExecutorBadSnapshot()
    c = TestClient(app, raise_server_exceptions=True)
    with pytest.raises(Exception) as excinfo:
        c.get("/v1/net/self")
    assert "net_self_snapshot_failed" in str(excinfo.value)


def test_status_mempool_invalid_limit_fails_closed_in_prod(monkeypatch):
    monkeypatch.setenv("WEALL_MODE", "prod")
    monkeypatch.setenv("WEALL_STATUS_MEMPOOL_LIMIT", "bogus")
    app = create_app(boot_runtime=False)
    c = TestClient(app, raise_server_exceptions=True)
    with pytest.raises(Exception) as excinfo:
        c.get("/v1/status/mempool")
    assert "invalid_integer_env:WEALL_STATUS_MEMPOOL_LIMIT" in str(excinfo.value)
