from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from weall.api.app import create_app


class _FakePool:
    def __init__(self, items=None) -> None:
        self._items = list(items or [])

    def size(self) -> int:
        return len(self._items)


class _FakeExecutor:
    def __init__(self) -> None:
        self.node_id = "@validator-2"
        self.mempool = _FakePool([{"tx_id": "tx:1"}])
        self.attestation_pool = _FakePool([])
        self.block_loop_running = True
        self.block_loop_unhealthy = False
        self.block_loop_last_error = ""
        self.block_loop_consecutive_failures = 0
        self._schema_version_cached = "1"

    def read_state(self) -> dict[str, object]:
        return {
            "chain_id": "obs-test",
            "height": 1,
            "tip": "1:block",
            "roles": {
                "validators": {"active_set": ["@validator-1", "@validator-2", "@validator-3"]}
            },
            "bft": {"view": 1},
            "meta": {"schema_version": "1", "tx_index_hash": "txindexhash-obs"},
            "accounts": {},
            "blocks": {},
            "params": {},
            "poh": {},
        }

    def snapshot(self) -> dict[str, object]:
        return self.read_state()

    def tx_index_hash(self) -> str:
        return "txindexhash-obs"


class _FakeNetNode:
    def peers_debug(self) -> dict[str, object]:
        return {
            "ok": True,
            "enabled": True,
            "counts": {
                "peers_total": 1,
                "peers_established": 1,
                "peers_identity_verified": 1,
                "peers_banned": 0,
            },
            "peers": [
                {"peer_id": "p1", "established": True, "identity_verified": True, "banned": False}
            ],
        }


def test_session_create_prod_fails_closed_on_invalid_max_json_env(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("WEALL_MODE", "prod")
    monkeypatch.setenv("WEALL_MAX_JSON_BYTES", "bogus")

    app = create_app(boot_runtime=False)
    client = TestClient(app, raise_server_exceptions=False)

    r = client.post("/v1/session/create", json={"account": "@demo", "session_key": "sk"})
    assert r.status_code == 500


def test_session_create_dev_still_falls_back_on_invalid_max_json_env(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("WEALL_MODE", "dev")
    monkeypatch.setenv("WEALL_MAX_JSON_BYTES", "bogus")

    app = create_app(boot_runtime=False)
    client = TestClient(app, raise_server_exceptions=False)

    r = client.post("/v1/session/create", json={"account": "@demo", "session_key": "sk"})
    assert r.status_code in {400, 500}
    assert r.status_code == 500 or r.json()["error"]["code"] in {
        "not_ready",
        "account_not_found",
        "state_invalid",
    }


def test_status_operator_prod_fails_closed_on_invalid_public_debug_env(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("WEALL_MODE", "prod")
    monkeypatch.setenv("WEALL_ENABLE_PUBLIC_DEBUG", "maybe")
    monkeypatch.setenv("WEALL_BFT_ENABLED", "1")
    monkeypatch.setenv("WEALL_NET_ENABLED", "1")

    app = create_app(boot_runtime=False)
    app.state.executor = _FakeExecutor()
    app.state.net_node = _FakeNetNode()
    client = TestClient(app, raise_server_exceptions=False)

    r = client.get("/v1/status/operator")
    assert r.status_code == 500


def test_net_debug_prod_fails_closed_on_invalid_public_debug_env(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("WEALL_MODE", "prod")
    monkeypatch.setenv("WEALL_ENABLE_PUBLIC_DEBUG", "maybe")

    app = create_app(boot_runtime=False)
    app.state.net_node = _FakeNetNode()
    client = TestClient(app, raise_server_exceptions=False)

    r = client.get("/v1/net/peers")
    assert r.status_code == 500


def test_block_producer_main_fails_closed_on_invalid_allow_empty_bool(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from weall.services import block_producer as svc

    monkeypatch.setenv("WEALL_PRODUCER_ALLOW_EMPTY", "maybe")

    rc = svc.main()
    assert rc == 2
