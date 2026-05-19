from __future__ import annotations

import hashlib
from pathlib import Path

from fastapi.testclient import TestClient

from weall.api.app import create_app

CID = "QmYwAPJzv5CZsnAzt8auVZRnGzr1rRkNvztNFVQVw1Gc7Y"


class _FakeExecutor:
    def __init__(self, state: dict):
        self._state = state

    def read_state(self) -> dict:
        return self._state


def _client_for_state(state: dict) -> TestClient:
    app = create_app(boot_runtime=False)
    app.state.executor = _FakeExecutor(state)
    return TestClient(app)


def _state_with_media_posts(count: int = 4) -> dict:
    posts: dict[str, dict] = {}
    for i in range(count):
        pid = f"post:{i}"
        posts[pid] = {
            "id": pid,
            "post_id": pid,
            "author": "@alice" if i % 2 == 0 else "@bob",
            "body": f"post {i}",
            "visibility": "public",
            "tags": ["media", f"n{i}"],
            "media": ["media:1"] if i == 0 else [],
            "created_nonce": i + 1,
            "created_at_nonce": i + 1,
        }
    return {
        "chain_id": "batch355",
        "content": {
            "posts": posts,
            "media": {
                "media:1": {
                    "media_id": "media:1",
                    "declared_by": "@alice",
                    "declared_at_nonce": 5,
                    "payload": {
                        "cid": CID,
                        "mime": "image/png",
                        "name": "demo.png",
                        "size_bytes": 1234,
                    },
                }
            },
            "reactions": {},
        },
    }


def test_public_feed_is_paginated_and_returns_media_metadata_only_batch355() -> None:
    client = _client_for_state(_state_with_media_posts(4))

    r = client.get("/v1/feed?limit=2")
    assert r.status_code == 200
    body = r.json()
    assert body["ok"] is True
    assert len(body["items"]) == 2
    assert body["next_cursor"]

    newest = body["items"][0]
    assert newest["post_id"] == "post:3"
    first_media_post = client.get("/v1/feed?limit=4").json()["items"][-1]
    media = first_media_post["media"][0]
    assert media["media_id"] == "media:1"
    assert media["cid"] == CID
    assert media["mime"] == "image/png"
    assert media["load_policy"] == "viewport"
    assert media["fetch_path"] == f"/v1/media/proxy/{CID}"
    assert "bytes" not in first_media_post
    assert "blob" not in media
    assert "data" not in media


def test_public_feed_cursor_and_filters_remain_bounded_batch355() -> None:
    client = _client_for_state(_state_with_media_posts(5))

    first = client.get("/v1/feed?limit=2&author=@alice&tags=media").json()
    assert len(first["items"]) == 2
    assert all(item["author"] == "@alice" for item in first["items"])
    assert first["next_cursor"]

    second = client.get(f"/v1/feed?limit=2&author=@alice&tags=media&cursor={first['next_cursor']}").json()
    assert len(second["items"]) <= 2
    assert [item["post_id"] for item in first["items"]] != [item["post_id"] for item in second["items"]]


def test_media_resolve_is_bounded_metadata_only_batch355() -> None:
    client = _client_for_state(_state_with_media_posts(1))

    r = client.get("/v1/media/resolve?ids=media:1,missing,media:1")
    assert r.status_code == 200
    body = r.json()
    assert body["ok"] is True
    assert body["count"] == 1
    assert body["missing"] == ["missing"]
    item = body["items"]["media:1"]
    assert item["cid"] == CID
    assert item["load_policy"] == "viewport"
    assert item["fetch_path"] == f"/v1/media/proxy/{CID}"
    assert "blob" not in item
    assert "data" not in item


def test_media_proxy_serves_local_cache_without_provider_fetch_batch355(tmp_path: Path, monkeypatch) -> None:
    cache_dir = tmp_path / "media-cache"
    monkeypatch.setenv("WEALL_MEDIA_CACHE_DIR", str(cache_dir))
    monkeypatch.setenv("WEALL_MEDIA_PROXY_FETCH_ENABLED", "0")

    digest = hashlib.sha256(CID.encode("utf-8")).hexdigest()
    cached = cache_dir / digest[:2] / f"{digest}.bin"
    cached.parent.mkdir(parents=True)
    cached.write_bytes(b"cached-media")

    client = _client_for_state(_state_with_media_posts(1))
    r = client.get(f"/v1/media/proxy/{CID}")
    assert r.status_code == 200
    assert r.headers.get("x-weall-media-cache") == "hit"
    assert r.headers.get("x-weall-media-load-policy") == "viewport"
    assert r.content == b"cached-media"


def test_media_proxy_does_not_fetch_when_observer_fetch_disabled_batch355(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("WEALL_MEDIA_CACHE_DIR", str(tmp_path / "media-cache"))
    monkeypatch.setenv("WEALL_MEDIA_PROXY_FETCH_ENABLED", "0")

    client = _client_for_state(_state_with_media_posts(1))
    r = client.get(f"/v1/media/proxy/{CID}")
    assert r.status_code == 404
    body = r.json()
    assert body.get("error", {}).get("code") == "media_not_cached"
