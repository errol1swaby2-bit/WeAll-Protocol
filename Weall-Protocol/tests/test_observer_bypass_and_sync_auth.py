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


def test_observer_edge_disables_legacy_mempool_submit_batch367(monkeypatch) -> None:
    monkeypatch.setenv("WEALL_OBSERVER_EDGE_MODE", "1")
    monkeypatch.delenv("WEALL_OBSERVER_EDGE_ALLOW_MEMPOOL_SUBMIT", raising=False)

    with _client() as client:
        res = client.post("/v1/mempool/submit", json={"tx_type": "ACCOUNT_REGISTER"})

    assert res.status_code == 403, res.text
    assert res.json()["error"]["code"] == "observer_edge_mempool_submit_disabled"
    assert res.json()["error"]["details"]["replacement"] == "/v1/tx/submit"


def test_prod_state_sync_request_requires_operator_token_batch367(monkeypatch) -> None:
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


def test_observer_upstream_state_sync_requests_send_operator_token_batch367(monkeypatch) -> None:
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


def test_media_gateway_legacy_redirect_is_removed_batch626(monkeypatch) -> None:
    cid = _cidv1_raw_sha256(b"legacy gateway cid")
    monkeypatch.setenv("WEALL_MODE", "prod")
    monkeypatch.delenv("WEALL_MEDIA_GATEWAY_ALLOW_DIRECT_REDIRECT", raising=False)

    with _client() as client:
        res = client.get(f"/v1/media/gateway/{cid}", follow_redirects=False)

    assert res.status_code == 410, res.text
    assert res.json()["error"]["code"] == "legacy_endpoint_removed"


def test_media_provider_urls_need_token_even_on_loopback_in_prod_batch367(monkeypatch) -> None:
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


def test_onboarding_boot_wrapper_sets_secure_observer_defaults_batch367() -> None:
    from pathlib import Path

    root = Path(__file__).resolve().parents[1]
    script = (root / "scripts" / "boot_onboarding_node.sh").read_text(encoding="utf-8")
    assert 'WEALL_STATE_SYNC_REQUEST_REQUIRE_OPERATOR_TOKEN="${WEALL_STATE_SYNC_REQUEST_REQUIRE_OPERATOR_TOKEN:-1}"' in script
    assert 'WEALL_MEDIA_GATEWAY_ALLOW_DIRECT_REDIRECT="${WEALL_MEDIA_GATEWAY_ALLOW_DIRECT_REDIRECT:-0}"' in script
    assert 'WEALL_MEDIA_REQUIRE_OPERATOR_TOKEN_FOR_LOCAL="${WEALL_MEDIA_REQUIRE_OPERATOR_TOKEN_FOR_LOCAL:-1}"' in script
