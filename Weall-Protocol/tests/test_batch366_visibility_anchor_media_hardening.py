from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path
from types import SimpleNamespace
from typing import Any

from fastapi.testclient import TestClient

from weall.api.app import create_app


class _FakeExecutor:
    chain_id = "batch366"

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


def _client(state: dict[str, Any]) -> TestClient:
    app = create_app(boot_runtime=False)
    app.state.executor = _FakeExecutor(state)
    app.state.net_node = None
    return TestClient(app, raise_server_exceptions=False)


def _visibility_state() -> dict[str, Any]:
    return {
        "chain_id": "batch366",
        "height": 3,
        "time": 10,
        "accounts": {
            "@member": {"nonce": 0, "poh_tier": 2, "session_keys": {"member-session": {"active": True}}},
            "@outsider": {"nonce": 0, "poh_tier": 2, "session_keys": {"outsider-session": {"active": True}}},
        },
        "groups_by_id": {
            "gpub": {
                "id": "gpub",
                "visibility": "public",
                "members": {"@member": {"role": "member"}},
            }
        },
        "content": {
            "posts": {
                "post:pub": {
                    "post_id": "post:pub",
                    "id": "post:pub",
                    "group_id": "gpub",
                    "author": "@member",
                    "body": "public group post",
                    "visibility": "public",
                    "created_nonce": 3,
                    "created_at_nonce": 3,
                },
                "post:priv": {
                    "post_id": "post:priv",
                    "id": "post:priv",
                    "group_id": "gpub",
                    "author": "@member",
                    "body": "public group post",
                    "visibility": "private",
                    "created_nonce": 2,
                    "created_at_nonce": 2,
                },
                "post:thread": {
                    "post_id": "post:thread",
                    "id": "post:thread",
                    "author": "@member",
                    "body": "public root",
                    "visibility": "public",
                    "created_nonce": 1,
                    "created_at_nonce": 1,
                },
            },
            "comments": {
                "comment:pub": {
                    "comment_id": "comment:pub",
                    "id": "comment:pub",
                    "post_id": "post:thread",
                    "author": "@member",
                    "body": "public comment",
                    "visibility": "public",
                    "created_nonce": 4,
                    "created_at_nonce": 4,
                },
                "comment:priv": {
                    "comment_id": "comment:priv",
                    "id": "comment:priv",
                    "post_id": "post:thread",
                    "author": "@member",
                    "body": "private comment",
                    "visibility": "private",
                    "created_nonce": 5,
                    "created_at_nonce": 5,
                },
            },
            "media": {},
            "reactions": {},
        },
    }


def _headers(account: str = "@member", session: str = "member-session") -> dict[str, str]:
    return {"X-WeAll-Account": account, "X-WeAll-Session-Key": session}


def test_public_group_content_and_feed_default_to_public_posts_batch366() -> None:
    with _client(_visibility_state()) as client:
        content = client.get("/v1/groups/gpub/content")
        assert content.status_code == 200, content.text
        assert [item["post_id"] for item in content.json()["items"]] == ["post:pub"]

        feed = client.get("/v1/groups/gpub/feed")
        assert feed.status_code == 200, feed.text
        assert [item["post_id"] for item in feed.json()["items"]] == ["post:pub"]

        anon_private = client.get("/v1/groups/gpub/content?visibility=private")
        assert anon_private.status_code == 400, anon_private.text
        assert anon_private.json()["error"]["code"] == "PUBLIC_READ_VISIBILITY_REQUIRED"

        member_private = client.get(
            "/v1/groups/gpub/content?visibility=private", headers=_headers()
        )
        assert member_private.status_code == 400, member_private.text
        assert member_private.json()["error"]["code"] == "PUBLIC_READ_VISIBILITY_REQUIRED"

        outsider_private = client.get(
            "/v1/groups/gpub/content?visibility=private",
            headers=_headers("@outsider", "outsider-session"),
        )
        assert outsider_private.status_code == 400, outsider_private.text
        assert outsider_private.json()["error"]["code"] == "PUBLIC_READ_VISIBILITY_REQUIRED"


def test_public_thread_filters_private_comments_batch366() -> None:
    with _client(_visibility_state()) as client:
        res = client.get("/v1/thread/post:thread")
        assert res.status_code == 200, res.text
        comments = res.json()["comments"]
        assert [c["comment_id"] for c in comments] == ["comment:pub"]
        assert "private comment" not in json.dumps(res.json())


def test_observer_state_sync_request_includes_trusted_anchor_batch366(monkeypatch) -> None:
    from weall.api.routes_public_parts import tx as tx_routes

    captured: dict[str, Any] = {}
    anchor = {
        "height": 7,
        "tip_hash": "tip:7",
        "state_root": "root:7",
        "finalized_height": 7,
        "finalized_block_id": "block:7",
    }

    def fake_get(url: str, path: str, *, timeout_s: int) -> dict[str, Any]:
        if path == "/v1/chain/identity":
            return {"ok": True, "chain_id": "batch366", "snapshot_anchor": anchor}
        if path == "/v1/chain/manifest":
            return {"ok": True, "chain_id": "batch366"}
        raise AssertionError(path)

    def fake_post(url: str, path: str, payload: dict[str, Any], *, timeout_s: int) -> dict[str, Any]:
        captured["url"] = url
        captured["path"] = path
        captured["payload"] = payload
        return {"ok": False, "response": {"bad": True}}

    class _SyncExecutor:
        chain_id = "batch366"

        def read_state(self):
            return self.snapshot()
        def snapshot(self) -> dict[str, Any]:
            return {"chain_id": "batch366", "height": 2}

        def apply_state_sync_response(self, *args: Any, **kwargs: Any) -> list[Any]:
            raise AssertionError("bad response should not be applied")

    request = SimpleNamespace(app=SimpleNamespace(state=SimpleNamespace(executor=_SyncExecutor())))
    monkeypatch.setenv("WEALL_TX_UPSTREAM_REQUIRE_MANIFEST", "0")
    monkeypatch.setattr(tx_routes, "_upstream_get_json", fake_get)
    monkeypatch.setattr(tx_routes, "_upstream_post_json", fake_post)

    result = tx_routes._request_and_apply_state_sync_from_upstream(
        request, "https://genesis.example.test", tx_id="tx:abc", target_height=7, timeout_s=3
    )

    assert result["ok"] is False
    assert captured["path"] == "/v1/sync/request"
    assert captured["payload"]["selector"] == {"tx_id": "tx:abc", "trusted_anchor": anchor}


def test_media_proxy_redacts_provider_url_from_headers_and_errors_batch366(tmp_path: Path, monkeypatch) -> None:
    good = b"batch366 media bytes"
    cid = _cidv1_raw_sha256(good)
    internal = f"https://lan.internal.example/ipfs/{cid}"
    state = {
        "chain_id": "batch366",
        "content": {"media": {"media:1": {"payload": {"cid": cid, "size_bytes": len(good)}}}},
    }

    def ok_urlopen(req, timeout=0):  # noqa: ANN001
        assert req.full_url == internal
        return _BytesResponse(good)

    monkeypatch.setenv("WEALL_MODE", "prod")
    monkeypatch.setenv("WEALL_MEDIA_CACHE_DIR", str(tmp_path / "cache-good"))
    monkeypatch.setenv("WEALL_MEDIA_PROVIDER_URLS", "https://lan.internal.example/ipfs/{cid}")
    monkeypatch.setattr("weall.api.routes_public_parts.media.urllib.request.urlopen", ok_urlopen)

    with _client(state) as client:
        res = client.get(f"/v1/media/proxy/{cid}")
        assert res.status_code == 200, res.text
        assert res.headers.get("x-weall-media-provider-kind") == "ipfs_gateway"
        assert res.headers.get("x-weall-media-provider-redacted") == "1"
        assert res.headers.get("x-weall-media-provider") is None
        assert "lan.internal" not in json.dumps(dict(res.headers)).lower()

    def bad_urlopen(req, timeout=0):  # noqa: ANN001
        return _BytesResponse(b"tampered")

    monkeypatch.setenv("WEALL_MEDIA_CACHE_DIR", str(tmp_path / "cache-bad"))
    monkeypatch.setattr("weall.api.routes_public_parts.media.urllib.request.urlopen", bad_urlopen)

    with _client(state) as client:
        bad = client.get(f"/v1/media/proxy/{cid}")
        assert bad.status_code == 400, bad.text
        body = bad.json()
        assert body["error"]["code"] == "media_provider_unavailable"
        assert "lan.internal" not in json.dumps(body).lower()
        providers = body["error"]["details"]["providers"]
        assert providers and providers[0]["redacted"] is True


def test_media_proxy_cache_disabled_redirect_fails_closed_in_prod_batch366(monkeypatch) -> None:
    data = b"redirect would bypass verification"
    cid = _cidv1_raw_sha256(data)
    monkeypatch.setenv("WEALL_MODE", "prod")
    monkeypatch.setenv("WEALL_MEDIA_PROXY_CACHE_ENABLED", "0")
    monkeypatch.setenv("WEALL_MEDIA_PROVIDER_URLS", "https://lan.internal.example/ipfs/{cid}")

    with _client({"chain_id": "batch366", "content": {"media": {}}}) as client:
        res = client.get(f"/v1/media/proxy/{cid}")
        assert res.status_code == 403, res.text
        assert res.json()["error"]["code"] == "media_unverified_redirect_forbidden"
