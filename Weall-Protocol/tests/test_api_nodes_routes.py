from __future__ import annotations

import json
from types import SimpleNamespace

from fastapi.testclient import TestClient

from weall.api.app import create_app


def test_nodes_seeds_merges_registry_and_env(tmp_path, monkeypatch):
    reg_path = tmp_path / "nodes_registry.json"
    reg_path.write_text(
        json.dumps(
            {
                "version": 7,
                "nodes": [
                    {"base_url": "https://alpha.example.com/", "role": "public", "region": "us", "weight": 5},
                    {"base_url": "https://beta.example.com", "role": "public", "region": "eu", "weight": 1},
                    {"base_url": "http://evil.example.com", "role": "public"},  # rejected
                    {"base_url": "", "role": "public"},  # rejected
                ],
            }
        ),
        encoding="utf-8",
    )

    monkeypatch.setenv("WEALL_NODES_REGISTRY_PATH", str(reg_path))
    monkeypatch.setenv("WEALL_API_MODE", "dev")
    monkeypatch.setenv("WEALL_ALLOW_INSECURE_LOCALHOST", "1")

    # Add env seeds (including localhost allowed + a duplicate)
    monkeypatch.setenv(
        "WEALL_SEED_NODES",
        "https://beta.example.com, http://127.0.0.1:8000, https://gamma.example.com/",
    )

    app = create_app(boot_runtime=False)
    c = TestClient(app)

    r = c.get("/v1/nodes/seeds")
    assert r.status_code == 200
    j = r.json()
    assert j.get("ok") is True
    assert j.get("version") == 7

    urls = [n["base_url"] for n in j.get("nodes", [])]
    assert "https://alpha.example.com" in urls
    assert "https://beta.example.com" in urls
    assert "https://gamma.example.com" in urls
    assert "http://127.0.0.1:8000" in urls

    # Ensure invalid http non-localhost was rejected.
    assert "http://evil.example.com" not in urls

    # Ensure dedupe occurred (beta only once).
    assert urls.count("https://beta.example.com") == 1


def test_nodes_known_empty_when_no_net_node(monkeypatch):
    app = create_app(boot_runtime=False)
    c = TestClient(app)

    r = c.get("/v1/nodes/known")
    assert r.status_code == 200
    j = r.json()
    assert j.get("ok") is True
    assert j.get("peers") == []


def test_nodes_known_reports_connected_peers(monkeypatch):
    app = create_app(boot_runtime=False)

    # Fake net node with peer ids and a minimal session map.
    class _FakeAddr(SimpleNamespace):
        uri: str

    class _FakeSession(SimpleNamespace):
        pass

    class _FakeNode:
        def __init__(self):
            self._peers = {
                "tcp://1.2.3.4:5555": _FakeSession(
                    addr=_FakeAddr(uri="tcp://1.2.3.4:5555"),
                    established=True,
                    last_seen_ms=123,
                    identity_verified=True,
                    account_id="@alice",
                )
            }

        def peer_ids(self):
            return ["tcp://1.2.3.4:5555"]

    app.state.net_node = _FakeNode()

    c = TestClient(app)
    r = c.get("/v1/nodes/known")
    assert r.status_code == 200
    j = r.json()
    assert j.get("ok") is True
    peers = j.get("peers")
    assert isinstance(peers, list)
    assert len(peers) == 1
    p0 = peers[0]
    assert p0.get("peer_id") == "tcp://1.2.3.4:5555"
    assert p0.get("addr") == "tcp://1.2.3.4:5555"
    assert p0.get("established") is True
    assert p0.get("last_seen_ms") == 123
    assert p0.get("identity_verified") is True
    assert p0.get("account_id") == "@alice"
