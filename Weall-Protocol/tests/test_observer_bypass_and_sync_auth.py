from __future__ import annotations

import base64
import hashlib
import json
from typing import Any

from fastapi.testclient import TestClient

from weall.api.app import create_app


class _FakeExecutor:
    chain_id = "batch367"

    def __init__(self, state: dict[str, Any] | None = None) -> None:
        self._state = state or {"chain_id": "batch367", "height": 0, "content": {"media": {}}}

    def read_state(self) -> dict[str, Any]:
        return self._state

    def snapshot(self) -> dict[str, Any]:
        return self._state


class _FakeResponse:
    def __init__(self, payload: dict[str, Any]) -> None:
        self.payload = payload

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb) -> bool:
        return False

    def read(self, _limit: int | None = None) -> bytes:
        return json.dumps(self.payload, sort_keys=True).encode("utf-8")


def _varint(value: int) -> bytes:
    out = bytearray()
    n = int(value)
    while True:
        b = n & 0x7F
        n >>= 7
        if n:
            out.append(b | 0x80)
        else:
            out.append(b)
            return bytes(out)


def _cidv1_raw_sha256(data: bytes) -> str:
    digest = hashlib.sha256(data).digest()
    raw = _varint(1) + _varint(0x55) + _varint(0x12) + _varint(len(digest)) + digest
    return "b" + base64.b32encode(raw).decode("ascii").lower().rstrip("=")


def _client(state: dict[str, Any] | None = None) -> TestClient:
    app = create_app(boot_runtime=False)
    app.state.executor = _FakeExecutor(state)
    app.state.net_node = None
    return TestClient(app, raise_server_exceptions=False)


def test_observer_edge_disables_legacy_mempool_submit(monkeypatch) -> None:
    monkeypatch.setenv("WEALL_OBSERVER_EDGE_MODE", "1")
    monkeypatch.delenv("WEALL_OBSERVER_EDGE_ALLOW_MEMPOOL_SUBMIT", raising=False)

    with _client() as client:
        res = client.post("/v1/mempool/submit", json={"tx_type": "ACCOUNT_REGISTER"})

    assert res.status_code == 403, res.text
    assert res.json()["error"]["code"] == "observer_edge_mempool_submit_disabled"
    assert res.json()["error"]["details"]["replacement"] == "/v1/tx/submit"


def test_prod_state_sync_request_requires_operator_token(monkeypatch) -> None:
    monkeypatch.setenv("WEALL_MODE", "prod")
    monkeypatch.setenv("WEALL_ENABLE_STATE_SYNC_HTTP_REQUEST_ROUTE", "1")
    monkeypatch.delenv("WEALL_OPERATOR_TOKEN", raising=False)
    monkeypatch.delenv("WEALL_STATE_SYNC_OPERATOR_TOKEN", raising=False)

    with _client() as client:
        missing = client.post("/v1/sync/request", json={"mode": "delta"})
        assert missing.status_code == 403, missing.text
        assert missing.json()["detail"]["code"] == "state_sync_operator_token_required"

    monkeypatch.setenv("WEALL_STATE_SYNC_OPERATOR_TOKEN", "sync-secret")
    with _client() as client:
        bad = client.post("/v1/sync/request", json={"mode": "delta"}, headers={"X-WeAll-State-Sync-Operator-Token": "wrong"})
        assert bad.status_code == 403, bad.text
        assert bad.json()["detail"]["code"] == "forbidden"


def test_observer_upstream_state_sync_requests_send_operator_token(monkeypatch) -> None:
    from weall.api.routes_public_parts import tx as tx_routes

    captured: dict[str, Any] = {}

    def fake_urlopen(req, timeout=0):  # noqa: ANN001
        captured["url"] = req.full_url
        captured["headers"] = dict(req.header_items())
        captured["body"] = json.loads(req.data.decode("utf-8"))
        return _FakeResponse({"ok": True, "response": {"ok": True, "height": 0, "blocks": []}})

    monkeypatch.setenv("WEALL_STATE_SYNC_OPERATOR_TOKEN", "sync-secret")
    monkeypatch.setattr(tx_routes.urllib.request, "urlopen", fake_urlopen)

    out = tx_routes._upstream_post_json(
        "https://genesis.example.test",
        "/v1/sync/request",
        {"mode": "delta"},
        timeout_s=3,
    )

    assert out["ok"] is True
    assert captured["url"] == "https://genesis.example.test/v1/sync/request"
    assert captured["headers"]["X-weall-state-sync-operator-token"] == "sync-secret"
    assert captured["headers"]["X-weall-operator-token"] == "sync-secret"


def test_media_gateway_legacy_redirect_is_removed(monkeypatch) -> None:
    cid = _cidv1_raw_sha256(b"legacy gateway cid")
    monkeypatch.setenv("WEALL_MODE", "prod")
    monkeypatch.delenv("WEALL_MEDIA_GATEWAY_ALLOW_DIRECT_REDIRECT", raising=False)

    with _client() as client:
        res = client.get(f"/v1/media/gateway/{cid}", follow_redirects=False)

    assert res.status_code == 410, res.text
    assert res.json()["error"]["code"] == "legacy_endpoint_removed"


def test_media_provider_urls_need_token_even_on_loopback_in_prod(monkeypatch) -> None:
    cid = _cidv1_raw_sha256(b"provider topology")
    state = {
        "chain_id": "batch367",
        "height": 0,
        "content": {"media": {"media:1": {"payload": {"cid": cid}}}},
        "storage": {"pin_confirms": [{"cid": cid, "ok": True, "provider_url": "https://lan.internal.example/ipfs/{cid}"}]},
    }
    monkeypatch.setenv("WEALL_MODE", "prod")
    monkeypatch.setenv("WEALL_OPERATOR_TOKEN", "media-secret")
    monkeypatch.setenv("WEALL_MEDIA_PROVIDER_URLS", "https://edge.internal.example/ipfs/{cid}")
    monkeypatch.delenv("WEALL_MEDIA_REQUIRE_OPERATOR_TOKEN_FOR_LOCAL", raising=False)

    with _client(state) as client:
        public = client.get(f"/v1/media/providers/{cid}")
        assert public.status_code == 200, public.text
        assert public.json()["urls_redacted"] is True
        assert "internal.example" not in json.dumps(public.json())

        operator = client.get(f"/v1/media/providers/{cid}", headers={"X-WeAll-Operator-Token": "media-secret"})
        assert operator.status_code == 200, operator.text
        assert operator.json()["urls_redacted"] is False
        assert "edge.internal.example" in json.dumps(operator.json())


def test_onboarding_boot_wrapper_sets_secure_observer_defaults() -> None:
    from pathlib import Path

    root = Path(__file__).resolve().parents[1]
    script = (root / "scripts" / "boot_onboarding_node.sh").read_text(encoding="utf-8")
    assert 'WEALL_STATE_SYNC_REQUEST_REQUIRE_OPERATOR_TOKEN="${WEALL_STATE_SYNC_REQUEST_REQUIRE_OPERATOR_TOKEN:-1}"' in script
    assert 'WEALL_MEDIA_GATEWAY_ALLOW_DIRECT_REDIRECT="${WEALL_MEDIA_GATEWAY_ALLOW_DIRECT_REDIRECT:-0}"' in script
    assert 'WEALL_MEDIA_REQUIRE_OPERATOR_TOKEN_FOR_LOCAL="${WEALL_MEDIA_REQUIRE_OPERATOR_TOKEN_FOR_LOCAL:-1}"' in script


def test_observer_edge_latest_state_sync_uses_trusted_anchor_without_tx_id(monkeypatch) -> None:
    from weall.api.routes_public_parts import tx as tx_routes

    captured: dict[str, Any] = {}
    anchor = {
        "height": 4,
        "tip_hash": "tip:4",
        "state_root": "root:4",
        "finalized_height": 0,
        "finalized_block_id": "",
    }

    def fake_get(url: str, path: str, *, timeout_s: int) -> dict[str, Any]:
        if path == "/v1/chain/identity":
            return {"ok": True, "chain_id": "batch367", "snapshot_anchor": anchor}
        if path == "/v1/chain/manifest":
            return {"ok": True, "chain_id": "batch367"}
        raise AssertionError(path)

    def fake_post(url: str, path: str, payload: dict[str, Any], *, timeout_s: int) -> dict[str, Any]:
        captured["url"] = url
        captured["path"] = path
        captured["payload"] = payload
        return {
            "ok": True,
            "response": {
                "header": {
                    "type": "STATE_SYNC_RESPONSE",
                    "chain_id": "batch367",
                    "schema_version": "1",
                    "tx_index_hash": "0",
                    "corr_id": "sync-test",
                },
                "ok": True,
                "height": 4,
                "blocks": [{"height": 3, "block_id": "b3"}, {"height": 4, "block_id": "b4"}],
                "snapshot_anchor": anchor,
            },
        }

    class _SyncExecutor:
        chain_id = "batch367"

        def __init__(self) -> None:
            self.state = {"chain_id": "batch367", "height": 2}
            self.applied = False

        def read_state(self) -> dict[str, Any]:
            return dict(self.state)

        def apply_state_sync_response(self, resp, *, trusted_anchor=None, allow_snapshot_bootstrap=False):  # noqa: ANN001
            self.applied = True
            assert trusted_anchor == anchor
            assert allow_snapshot_bootstrap is False
            assert getattr(resp, "height", 0) == 4
            self.state["height"] = 4
            return [object(), object()]

    monkeypatch.setenv("WEALL_TX_UPSTREAM_REQUIRE_MANIFEST", "0")
    monkeypatch.setattr(tx_routes, "_upstream_get_json", fake_get)
    monkeypatch.setattr(tx_routes, "_upstream_post_json", fake_post)

    ex = _SyncExecutor()
    result = tx_routes._request_and_apply_latest_state_sync_from_upstream(
        ex, "https://genesis.example.test", timeout_s=3
    )

    assert result["ok"] is True
    assert result["source"] == "upstream_state_sync_latest"
    assert result["local_state_synced"] is True
    assert result["local_height_before"] == 2
    assert result["local_height"] == 4
    assert result["applied_count"] == 2
    assert ex.applied is True
    assert captured["path"] == "/v1/sync/request"
    assert captured["payload"]["from_height"] == 2
    assert captured["payload"]["to_height"] == 4
    assert captured["payload"]["selector"] == {"trusted_anchor": anchor}
    assert "tx_id" not in captured["payload"]["selector"]


def test_observer_edge_status_exposes_state_sync_autodrain(monkeypatch) -> None:
    monkeypatch.setenv("WEALL_OBSERVER_EDGE_MODE", "1")
    monkeypatch.setenv("WEALL_TX_QUEUE_AUTODRAIN", "1")
    monkeypatch.setenv("WEALL_TX_UPSTREAM_URLS", "http://127.0.0.1:8001")
    monkeypatch.setenv("WEALL_OPERATOR_TOKEN", "op-secret")

    with _client() as client:
        res = client.get("/v1/observer/edge/status", headers={"X-WeAll-Operator-Token": "op-secret"})

    assert res.status_code == 200, res.text
    body = res.json()
    assert body["ok"] is True
    assert body["state_sync_autodrain"]["enabled"] is True
    assert body["state_sync_autodrain"]["interval_s"] >= 0.25
