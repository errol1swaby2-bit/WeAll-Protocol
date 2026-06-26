from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path
from typing import Any

from fastapi.testclient import TestClient

from weall.api.app import create_app
from weall.util.ipfs_cid import verify_cid_multihash_bytes


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


class _FakeExecutor:
    chain_id = "batch365"

    def __init__(self, state: dict[str, Any]) -> None:
        self._state = state

    def read_state(self) -> dict[str, Any]:
        return self._state

    def snapshot(self) -> dict[str, Any]:
        return self._state


class _BytesResponse:
    def __init__(self, data: bytes) -> None:
        self._data = data
        self._pos = 0
        self.headers = {"Content-Length": str(len(data))}

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb) -> bool:
        return False

    def read(self, n: int | None = None) -> bytes:
        if self._pos >= len(self._data):
            return b""
        if n is None or n < 0:
            n = len(self._data) - self._pos
        chunk = self._data[self._pos : self._pos + n]
        self._pos += len(chunk)
        return chunk


def _client(state: dict[str, Any]) -> TestClient:
    app = create_app(boot_runtime=False)
    app.state.executor = _FakeExecutor(state)
    app.state.net_node = None
    return TestClient(app, raise_server_exceptions=False)


def _state_with_media(cid: str, *, include_sha: bool = False, data: bytes = b"") -> dict[str, Any]:
    payload: dict[str, Any] = {
        "cid": cid,
        "mime": "application/octet-stream",
        "size_bytes": len(data),
    }
    if include_sha:
        payload["sha256"] = hashlib.sha256(data).hexdigest()
    return {
        "chain_id": "batch365",
        "height": 0,
        "accounts": {"@alice": {"nonce": 0, "poh_tier": 2}},
        "content": {
            "posts": {
                "post:alice": {
                    "post_id": "post:alice",
                    "author": "@alice",
                    "body": "hello with media",
                    "visibility": "public",
                    "media": ["media:raw"],
                    "created_nonce": 1,
                    "created_at_nonce": 1,
                }
            },
            "comments": {},
            "media": {"media:raw": {"media_id": "media:raw", "payload": payload}},
            "reactions": {},
        },
        "storage": {"pin_confirms": [{"cid": cid, "ok": True, "provider_url": "https://provider.example.test/ipfs/{cid}"}]},
    }


def test_cidv1_raw_sha256_multihash_verifies_supported_bytes_batch365() -> None:
    data = b"raw cid bytes batch365"
    cid = _cidv1_raw_sha256(data)

    ok = verify_cid_multihash_bytes(cid, data)
    assert ok.ok is True
    assert ok.supported is True
    assert ok.reason == "cidv1_raw_sha2_256"

    bad = verify_cid_multihash_bytes(cid, b"tampered")
    assert bad.ok is False
    assert bad.supported is True
    assert bad.reason == "cid_multihash_mismatch"


def test_media_proxy_accepts_cid_verified_raw_bytes_without_committed_sha_batch365(tmp_path: Path, monkeypatch) -> None:
    data = b"raw cid bytes served through observer"
    cid = _cidv1_raw_sha256(data)
    calls: list[str] = []

    def fake_urlopen(req, timeout=0):  # noqa: ANN001
        calls.append(req.full_url)
        return _BytesResponse(data)

    monkeypatch.setenv("WEALL_MODE", "prod")
    monkeypatch.setenv("WEALL_MEDIA_CACHE_DIR", str(tmp_path / "cache"))
    monkeypatch.setenv("WEALL_MEDIA_PROVIDER_URLS", "https://edge.example.test/ipfs/{cid}")
    monkeypatch.setattr("weall.api.routes_public_parts.media.urllib.request.urlopen", fake_urlopen)

    with _client(_state_with_media(cid, data=data)) as client:
        res = client.get(f"/v1/media/proxy/{cid}")
        assert res.status_code == 200, res.text
        assert res.content == data
        assert res.headers.get("x-weall-media-byte-verified") == "cidv1_raw_sha2_256"
        assert calls == [f"https://edge.example.test/ipfs/{cid}"]


def test_media_proxy_rejects_supported_cid_multihash_mismatch_batch365(tmp_path: Path, monkeypatch) -> None:
    data = b"raw cid bytes expected"
    cid = _cidv1_raw_sha256(data)

    def fake_urlopen(_req, timeout=0):  # noqa: ANN001
        return _BytesResponse(b"wrong bytes")

    monkeypatch.setenv("WEALL_MODE", "prod")
    monkeypatch.setenv("WEALL_MEDIA_CACHE_DIR", str(tmp_path / "cache"))
    monkeypatch.setenv("WEALL_MEDIA_PROVIDER_URLS", "https://edge.example.test/ipfs/{cid}")
    monkeypatch.setattr("weall.api.routes_public_parts.media.urllib.request.urlopen", fake_urlopen)

    with _client(_state_with_media(cid, data=data)) as client:
        res = client.get(f"/v1/media/proxy/{cid}")
        assert res.status_code == 400, res.text
        assert res.json().get("error", {}).get("code") == "media_provider_unavailable"

    assert not list((tmp_path / "cache").rglob("*.bin"))


def test_media_providers_redacts_urls_in_prod_without_operator_auth_batch365(monkeypatch) -> None:
    data = b"raw provider data"
    cid = _cidv1_raw_sha256(data)
    monkeypatch.setenv("WEALL_MODE", "prod")
    monkeypatch.setenv("WEALL_MEDIA_PROVIDER_URLS", "https://lan.internal.example/ipfs/{cid}")

    with _client(_state_with_media(cid, data=data)) as client:
        public = client.get(f"/v1/media/providers/{cid}")
        assert public.status_code == 200, public.text
        body = public.json()
        assert body["urls_redacted"] is True
        assert body["providers"]
        assert all(isinstance(item, dict) and item.get("redacted") is True for item in body["providers"])
        assert "lan.internal" not in json.dumps(body)

        monkeypatch.setenv("WEALL_OPERATOR_TOKEN", "media-secret")
        operator = client.get(f"/v1/media/providers/{cid}", headers={"X-WeAll-Operator-Token": "media-secret"})
        assert operator.status_code == 200, operator.text
        assert operator.json()["urls_redacted"] is False
        assert operator.json()["providers"][0] == f"https://lan.internal.example/ipfs/{cid}"


def test_account_feed_returns_metadata_first_media_summaries_batch365() -> None:
    data = b"account feed media"
    cid = _cidv1_raw_sha256(data)
    with _client(_state_with_media(cid, data=data)) as client:
        res = client.get("/v1/accounts/@alice/feed")
        assert res.status_code == 200, res.text
        media = res.json()["items"][0]["media"][0]
        assert media["cid"] == cid
        assert media["fetch_path"] == f"/v1/media/proxy/{cid}"
        assert media["load_policy"] == "viewport"


def test_observer_reconcile_endpoint_marks_local_state_synced_only_after_local_apply_batch365(tmp_path: Path, monkeypatch) -> None:
    tx_id = "tx:batch365"
    tx_queue = tmp_path / "tx_queue.json"
    tx_queue.write_text(
        json.dumps(
            {
                "version": 2,
                "records": [
                    {
                        "tx_id": tx_id,
                        "chain_id": "batch365",
                        "created_ms": 1,
                        "updated_ms": 1,
                        "attempts": 1,
                        "upstream_status": "accepted",
                        "envelope": {"tx_type": "ACCOUNT_REGISTER", "signer": "@a", "nonce": 1, "chain_id": "batch365", "payload": {"pubkey": "00"}},
                    }
                ],
            }
        ),
        encoding="utf-8",
    )

    monkeypatch.setenv("WEALL_OBSERVER_EDGE_MODE", "1")
    monkeypatch.setenv("WEALL_TX_QUEUE_PATH", str(tx_queue))
    monkeypatch.setenv("WEALL_TX_UPSTREAM_URLS", "https://genesis.example.test")
    monkeypatch.setenv("WEALL_OPERATOR_TOKEN", "edge-secret")

    def fake_status(_url: str, _tx_id: str, *, timeout_s: int) -> dict[str, Any]:
        return {"ok": True, "tx_id": _tx_id, "status": "confirmed", "height": 4, "block_id": "block:4"}

    def fake_sync(request, url: str, *, tx_id: str, target_height: int, timeout_s: int) -> dict[str, Any]:  # noqa: ANN001
        from weall.api.routes_public_parts import tx as tx_routes

        tx_routes._update_tx_queue_record(
            tx_id,
            {
                "upstream_status": "confirmed",
                "local_state_synced": True,
                "confirmed_height": target_height,
                "confirmed_block_id": "block:4",
                "last_error": "",
            },
        )
        return {"ok": True, "local_state_synced": True, "upstream": url, "applied_count": 1}

    monkeypatch.setattr("weall.api.routes_public_parts.tx._status_from_upstream", fake_status)
    monkeypatch.setattr("weall.api.routes_public_parts.tx._request_and_apply_state_sync_from_upstream", fake_sync)

    with _client({"chain_id": "batch365", "height": 3, "content": {"posts": {}, "comments": {}, "media": {}}}) as client:
        res = client.post(f"/v1/observer/edge/reconcile/{tx_id}", headers={"X-WeAll-Operator-Token": "edge-secret"})
        assert res.status_code == 200, res.text
        body = res.json()
        assert body["ok"] is True
        assert body["local_state_synced"] is True
        assert body["source"] == "state_sync"


def test_observer_reconcile_endpoint_does_not_pretend_sync_when_apply_fails_batch365(tmp_path: Path, monkeypatch) -> None:
    tx_id = "tx:batch365-nosync"
    tx_queue = tmp_path / "tx_queue.json"
    tx_queue.write_text(
        json.dumps({"version": 2, "records": [{"tx_id": tx_id, "chain_id": "batch365", "created_ms": 1, "updated_ms": 1, "upstream_status": "accepted", "envelope": {"chain_id": "batch365"}}]}),
        encoding="utf-8",
    )
    monkeypatch.setenv("WEALL_OBSERVER_EDGE_MODE", "1")
    monkeypatch.setenv("WEALL_TX_QUEUE_PATH", str(tx_queue))
    monkeypatch.setenv("WEALL_TX_UPSTREAM_URLS", "https://genesis.example.test")
    monkeypatch.setenv("WEALL_OPERATOR_TOKEN", "edge-secret")
    monkeypatch.setattr(
        "weall.api.routes_public_parts.tx._status_from_upstream",
        lambda _url, _tx_id, timeout_s=0: {"ok": True, "tx_id": _tx_id, "status": "confirmed", "height": 5, "block_id": "block:5"},
    )
    monkeypatch.setattr(
        "weall.api.routes_public_parts.tx._request_and_apply_state_sync_from_upstream",
        lambda request, url, *, tx_id, target_height, timeout_s: {"ok": False, "error": "state_sync_apply_failed"},
    )

    with _client({"chain_id": "batch365", "height": 0, "content": {"posts": {}, "comments": {}, "media": {}}}) as client:
        res = client.post(f"/v1/observer/edge/reconcile/{tx_id}", headers={"X-WeAll-Operator-Token": "edge-secret"})
        assert res.status_code == 200, res.text
        body = res.json()
        assert body["ok"] is False
        assert body["local_state_synced"] is False
        assert body["error"] == "local_state_sync_failed"
