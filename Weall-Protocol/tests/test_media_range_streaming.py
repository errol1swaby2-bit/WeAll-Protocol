from __future__ import annotations

import base64
import hashlib
from pathlib import Path
from typing import Any

from fastapi.testclient import TestClient

from weall.api.app import create_app


class _FakeExecutor:
    chain_id = "batch369"

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


def _state_with_media(cid: str, data: bytes, *, mime: str = "video/mp4") -> dict[str, Any]:
    return {
        "chain_id": "batch369",
        "height": 1,
        "content": {
            "posts": {},
            "comments": {},
            "media": {
                "media:range": {
                    "media_id": "media:range",
                    "payload": {
                        "cid": cid,
                        "mime": mime,
                        "size_bytes": len(data),
                        "sha256": hashlib.sha256(data).hexdigest(),
                    },
                }
            },
            "reactions": {},
        },
        "storage": {},
    }


def _client(state: dict[str, Any]) -> TestClient:
    app = create_app(boot_runtime=False)
    app.state.executor = _FakeExecutor(state)
    app.state.net_node = None
    return TestClient(app, raise_server_exceptions=False)


def test_media_proxy_serves_single_byte_range_from_verified_cache(tmp_path: Path, monkeypatch) -> None:
    data = b"0123456789abcdefghijklmnopqrstuvwxyz"
    cid = _cidv1_raw_sha256(data)
    cache_dir = tmp_path / "cache"
    monkeypatch.setenv("WEALL_MODE", "prod")
    monkeypatch.setenv("WEALL_MEDIA_CACHE_DIR", str(cache_dir))
    monkeypatch.setenv("WEALL_MEDIA_PROVIDER_URLS", "https://provider.example/ipfs/{cid}")

    def fake_urlopen(_req, timeout=0):  # noqa: ANN001
        return _BytesResponse(data)

    monkeypatch.setattr("weall.api.routes_public_parts.media.urllib.request.urlopen", fake_urlopen)

    with _client(_state_with_media(cid, data)) as client:
        warm = client.get(f"/v1/media/proxy/{cid}")
        assert warm.status_code == 200, warm.text
        assert warm.content == data

        res = client.get(f"/v1/media/proxy/{cid}", headers={"Range": "bytes=10-15"})
        assert res.status_code == 206, res.text
        assert res.content == data[10:16]
        assert res.headers.get("accept-ranges") == "bytes"
        assert res.headers.get("content-range") == f"bytes 10-15/{len(data)}"
        assert res.headers.get("content-length") == "6"
        assert res.headers.get("x-weall-media-range") == "1"
        assert res.headers.get("x-weall-media-byte-verified") == "sha256"
        assert res.headers.get("content-type", "").startswith("video/mp4")


def test_media_proxy_fetches_verifies_then_serves_requested_range_on_cache_miss(tmp_path: Path, monkeypatch) -> None:
    data = b"abcdefghijklmnopqrstuvwxyz0123456789"
    cid = _cidv1_raw_sha256(data)
    calls: list[str] = []
    monkeypatch.setenv("WEALL_MODE", "prod")
    monkeypatch.setenv("WEALL_MEDIA_CACHE_DIR", str(tmp_path / "cache"))
    monkeypatch.setenv("WEALL_MEDIA_PROVIDER_URLS", "https://provider.example/ipfs/{cid}")

    def fake_urlopen(req, timeout=0):  # noqa: ANN001
        calls.append(req.full_url)
        return _BytesResponse(data)

    monkeypatch.setattr("weall.api.routes_public_parts.media.urllib.request.urlopen", fake_urlopen)

    with _client(_state_with_media(cid, data, mime="audio/mpeg")) as client:
        res = client.get(f"/v1/media/proxy/{cid}", headers={"Range": "bytes=-8"})
        assert res.status_code == 206, res.text
        assert res.content == data[-8:]
        assert res.headers.get("content-range") == f"bytes {len(data)-8}-{len(data)-1}/{len(data)}"
        assert res.headers.get("x-weall-media-cache") == "miss-store"
        assert res.headers.get("x-weall-media-byte-verified") == "sha256"
        assert res.headers.get("content-type", "").startswith("audio/mpeg")
        assert calls == [f"https://provider.example/ipfs/{cid}"]

        again = client.get(f"/v1/media/proxy/{cid}", headers={"Range": "bytes=0-2"})
        assert again.status_code == 206, again.text
        assert again.content == data[0:3]
        assert again.headers.get("x-weall-media-cache") == "hit"
        assert calls == [f"https://provider.example/ipfs/{cid}"]


def test_media_proxy_rejects_multi_range_and_unsatisfiable_ranges(tmp_path: Path, monkeypatch) -> None:
    data = b"0123456789"
    cid = _cidv1_raw_sha256(data)
    monkeypatch.setenv("WEALL_MODE", "prod")
    monkeypatch.setenv("WEALL_MEDIA_CACHE_DIR", str(tmp_path / "cache"))
    monkeypatch.setenv("WEALL_MEDIA_PROVIDER_URLS", "https://provider.example/ipfs/{cid}")

    def fake_urlopen(_req, timeout=0):  # noqa: ANN001
        return _BytesResponse(data)

    monkeypatch.setattr("weall.api.routes_public_parts.media.urllib.request.urlopen", fake_urlopen)

    with _client(_state_with_media(cid, data)) as client:
        warm = client.get(f"/v1/media/proxy/{cid}")
        assert warm.status_code == 200, warm.text

        multi = client.get(f"/v1/media/proxy/{cid}", headers={"Range": "bytes=0-1,3-4"})
        assert multi.status_code == 400, multi.text
        assert multi.json()["error"]["code"] == "media_range_invalid"

        miss = client.get(f"/v1/media/proxy/{cid}", headers={"Range": "bytes=99-100"})
        assert miss.status_code == 416, miss.text
        assert miss.json()["error"]["code"] == "media_range_not_satisfiable"


def test_public_state_snapshot_redacts_groups_by_id_member_maps() -> None:
    state = {
        "chain_id": "batch369",
        "height": 1,
        "groups_by_id": {
            "g:private": {
                "id": "g:private",
                "visibility": "private",
                "members": {"@alice": {"role": "admin", "joined_at_nonce": 1}},
            },
            "g:public": {"id": "g:public", "visibility": "public", "members": {"@bob": {}}},
        },
        "content": {"posts": {}, "comments": {}, "media": {}},
    }
    with _client(state) as client:
        res = client.get("/v1/state/snapshot")
        assert res.status_code == 200, res.text
        body = res.json()
        groups = body["state"]["groups_by_id"]
        assert groups["redacted"] is True
        assert groups["summary"] == {"total": 2, "public": 1, "private": 1}
        assert "@alice" not in str(body)
        assert "members" not in str(groups)
