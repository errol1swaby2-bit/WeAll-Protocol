from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any

from fastapi.testclient import TestClient

from weall.api.app import create_app

CID = "QmYwAPJzv5CZsnAzt8auVZRnGzr1rRkNvztNFVQVw1Gc7Y"


class _FakeExecutor:
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
    return TestClient(app, raise_server_exceptions=False)


def _auth(account: str) -> dict[str, str]:
    return {"x-weall-account": account, "x-weall-session-key": f"sk:{account}"}


def _state() -> dict[str, Any]:
    good = b"verified media bytes"
    return {
        "chain_id": "batch363-364",
        "accounts": {
            "@alice": {"nonce": 0, "poh_tier": 2, "session_keys": {"sk:@alice": {"active": True, "ttl_s": 0}}},
            "@bob": {"nonce": 0, "poh_tier": 2, "session_keys": {"sk:@bob": {"active": True, "ttl_s": 0}}},
            "@eve": {"nonce": 0, "poh_tier": 2, "session_keys": {"sk:@eve": {"active": True, "ttl_s": 0}}},
        },
        "groups_by_id": {
            "g-private": {
                "id": "g-private",
                "visibility": "private",
                "members": {"@alice": {"role": "member"}},
            },
            "g-public": {"id": "g-public", "visibility": "public", "members": {"@bob": {"role": "member"}}},
        },
        "content": {
            "posts": {
                "post:private": {
                    "post_id": "post:private",
                    "author": "@alice",
                    "body": "private note",
                    "visibility": "private",
                    "created_nonce": 1,
                },
                "post:g-private": {
                    "post_id": "post:g-private",
                    "author": "@alice",
                    "body": "public group note",
                    "visibility": "group",
                    "group_id": "g-private",
                    "media": ["media:verified"],
                    "created_nonce": 2,
                },
                "post:g-public": {
                    "post_id": "post:g-public",
                    "author": "@bob",
                    "body": "public group note",
                    "visibility": "public",
                    "group_id": "g-public",
                    "created_nonce": 3,
                },
            },
            "comments": {
                "comment:g-private": {
                    "comment_id": "comment:g-private",
                    "post_id": "post:g-private",
                    "author": "@alice",
                    "body": "public group reply",
                    "created_nonce": 4,
                }
            },
            "media": {
                "media:verified": {
                    "media_id": "media:verified",
                    "declared_by": "@alice",
                    "payload": {
                        "cid": CID,
                        "mime": "image/png",
                        "size_bytes": len(good),
                        "sha256": hashlib.sha256(good).hexdigest(),
                    },
                }
            },
            "reactions": {},
        },
        "storage": {
            "pin_confirms": [
                {
                    "cid": CID,
                    "ok": True,
                    "operator_id": "genesis-media",
                    "provider_url": "https://genesis.example.test/media/{cid}",
                }
            ]
        },
    }


def test_legacy_restricted_group_content_is_publicly_readable() -> None:
    with _client(_state()) as client:
        for headers in [None, _auth("@eve"), _auth("@alice")]:
            res = client.get("/v1/groups/g-private/content", headers=headers or {})
            assert res.status_code == 200, res.text
            body = res.json()
            assert body["ok"] is True
            assert body["items"][0]["post_id"] == "post:g-private"
            media = body["items"][0]["media"][0]
            assert media["fetch_path"] == f"/v1/media/proxy/{CID}"
            assert media["load_policy"] == "viewport"


def test_scoped_content_route_no_longer_exposes_private_archives() -> None:
    with _client(_state()) as client:
        assert client.get("/v1/content/post:private").status_code == 404

        # Legacy group-scoped content is now public-readable.  The historical
        # legacy group flag cannot create restricted reads
        # archive after the public-only redesign.
        group_public = client.get("/v1/content/post:g-private")
        assert group_public.status_code == 200, group_public.text
        assert group_public.json()["content"]["body"] == "public group note"

        private_author = client.get("/v1/content/post:private/scoped", headers=_auth("@alice"))
        assert private_author.status_code == 404

        private_non_owner = client.get("/v1/content/post:private/scoped", headers=_auth("@bob"))
        assert private_non_owner.status_code == 404

        group_member = client.get("/v1/content/post:g-private/scoped", headers=_auth("@alice"))
        assert group_member.status_code == 200, group_member.text
        assert group_member.json()["content"]["body"] == "public group note"

        group_non_member = client.get("/v1/content/post:g-private/scoped", headers=_auth("@eve"))
        assert group_non_member.status_code == 200, group_non_member.text
        assert group_non_member.json()["content"]["body"] == "public group note"

        comment_public = client.get("/v1/content/comment:g-private")
        assert comment_public.status_code == 200, comment_public.text
        assert comment_public.json()["content"]["body"] == "public group reply"


def test_group_member_list_is_public_activity() -> None:
    with _client(_state()) as client:
        for headers in [{}, _auth("@eve"), _auth("@alice")]:
            ok = client.get("/v1/groups/g-private/members", headers=headers)
            assert ok.status_code == 200, ok.text
            assert ok.json()["counts"]["total"] == 1


def test_media_provider_graph_is_metadata_only_and_ordered(monkeypatch) -> None:
    monkeypatch.setenv("WEALL_MEDIA_PROVIDER_URLS", "https://edge.example.test/ipfs/{cid}")
    with _client(_state()) as client:
        res = client.get(f"/v1/media/providers/{CID}")
        assert res.status_code == 200, res.text
        providers = res.json()["providers"]
        assert providers[0] == f"https://edge.example.test/ipfs/{CID}"
        assert f"https://genesis.example.test/media/{CID}" in providers
        assert any(url.endswith(f"/ipfs/{CID}") for url in providers)


def test_media_proxy_verifies_declared_sha256_before_cache(tmp_path: Path, monkeypatch) -> None:
    data = b"verified media bytes"
    calls: list[str] = []

    def fake_urlopen(req, timeout=0):  # noqa: ANN001
        calls.append(req.full_url)
        return _BytesResponse(data)

    monkeypatch.setenv("WEALL_MEDIA_CACHE_DIR", str(tmp_path / "cache"))
    monkeypatch.setenv("WEALL_MEDIA_PROVIDER_URLS", "https://edge.example.test/ipfs/{cid}")
    monkeypatch.setattr("weall.api.routes_public_parts.media.urllib.request.urlopen", fake_urlopen)

    with _client(_state()) as client:
        res = client.get(f"/v1/media/proxy/{CID}")
        assert res.status_code == 200, res.text
        assert res.content == data
        assert res.headers.get("x-weall-media-cache") == "miss-store"
        assert res.headers.get("x-weall-media-byte-verified") == "sha256"
        assert calls == [f"https://edge.example.test/ipfs/{CID}"]

        again = client.get(f"/v1/media/proxy/{CID}")
        assert again.status_code == 200
        assert again.headers.get("x-weall-media-cache") == "hit"
        assert again.headers.get("x-weall-media-byte-verified") == "sha256"
        assert calls == [f"https://edge.example.test/ipfs/{CID}"]


def test_media_proxy_rejects_and_does_not_cache_hash_mismatch(tmp_path: Path, monkeypatch) -> None:
    def fake_urlopen(_req, timeout=0):  # noqa: ANN001
        return _BytesResponse(b"tampered bytes")

    monkeypatch.setenv("WEALL_MEDIA_CACHE_DIR", str(tmp_path / "cache"))
    monkeypatch.setenv("WEALL_MEDIA_PROVIDER_URLS", "https://edge.example.test/ipfs/{cid}")
    monkeypatch.setattr("weall.api.routes_public_parts.media.urllib.request.urlopen", fake_urlopen)

    with _client(_state()) as client:
        res = client.get(f"/v1/media/proxy/{CID}")
        assert res.status_code == 400, res.text
        assert res.json().get("error", {}).get("code") == "media_provider_unavailable"

    assert not list((tmp_path / "cache").rglob("*.bin"))
