from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path
from typing import Any

from fastapi.testclient import TestClient

from weall.api.app import create_app


class _FakeExecutor:
    chain_id = "batch370"

    def __init__(self, state: dict[str, Any] | None = None) -> None:
        self._state = state or {"chain_id": "batch370", "height": 0, "content": {"media": {}}}

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


class _JsonResponse:
    def __init__(self, payload: dict[str, Any]) -> None:
        self.payload = payload
        self.headers = {"Content-Type": "application/json"}

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb) -> bool:
        return False

    def read(self, n: int | None = None) -> bytes:
        return json.dumps(self.payload).encode("utf-8")


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


def _state_with_media(cid: str, data: bytes) -> dict[str, Any]:
    return {
        "chain_id": "batch370",
        "height": 1,
        "content": {
            "posts": {},
            "comments": {},
            "media": {
                "media:cache": {
                    "media_id": "media:cache",
                    "payload": {
                        "cid": cid,
                        "mime": "video/mp4",
                        "size_bytes": len(data),
                        "sha256": hashlib.sha256(data).hexdigest(),
                    },
                }
            },
            "reactions": {},
        },
        "storage": {},
    }


def _client(state: dict[str, Any] | None = None) -> TestClient:
    app = create_app(boot_runtime=False)
    app.state.executor = _FakeExecutor(state)
    app.state.net_node = None
    return TestClient(app, raise_server_exceptions=False)


def test_verified_media_cache_metadata_avoids_full_rehash_on_range_hit_batch370(tmp_path: Path, monkeypatch) -> None:
    from weall.api.routes_public_parts import media as media_routes

    data = b"0123456789" * 32
    cid = _cidv1_raw_sha256(data)
    monkeypatch.setenv("WEALL_MODE", "prod")
    monkeypatch.setenv("WEALL_MEDIA_CACHE_DIR", str(tmp_path / "cache"))
    monkeypatch.setenv("WEALL_MEDIA_PROVIDER_URLS", "https://provider.example/ipfs/{cid}")

    def fake_urlopen(_req, timeout=0):  # noqa: ANN001
        return _BytesResponse(data)

    monkeypatch.setattr(media_routes.urllib.request, "urlopen", fake_urlopen)

    with _client(_state_with_media(cid, data)) as client:
        warm = client.get(f"/v1/media/proxy/{cid}")
        assert warm.status_code == 200, warm.text
        assert warm.headers.get("x-weall-media-byte-verified") == "sha256"

        cache_path = media_routes._cache_path_for_cid(cid)
        meta_path = media_routes._cache_meta_path(cache_path)
        assert cache_path.exists()
        meta = json.loads(meta_path.read_text(encoding="utf-8"))
        assert meta["cid"] == cid
        assert meta["size"] == len(data)
        assert meta["sha256"] == hashlib.sha256(data).hexdigest()
        assert meta["verification"] == "sha256"

        def fail_full_reverify(**_kwargs):  # noqa: ANN003
            raise AssertionError("range cache hit should trust verified metadata, not rehash full file")

        monkeypatch.setattr(media_routes, "_verify_cached_media_bytes", fail_full_reverify)
        res = client.get(f"/v1/media/proxy/{cid}", headers={"Range": "bytes=10-19"})
        assert res.status_code == 206, res.text
        assert res.content == data[10:20]
        assert res.headers.get("x-weall-media-cache") == "hit"
        assert res.headers.get("x-weall-media-range") == "1"
        assert res.headers.get("x-weall-media-byte-verified") == "sha256"


def test_verified_media_cache_strict_reverify_can_force_full_hash_batch370(tmp_path: Path, monkeypatch) -> None:
    from weall.api.routes_public_parts import media as media_routes

    data = b"strict reverify bytes"
    cid = _cidv1_raw_sha256(data)
    calls = {"verify": 0}
    monkeypatch.setenv("WEALL_MODE", "prod")
    monkeypatch.setenv("WEALL_MEDIA_CACHE_DIR", str(tmp_path / "cache"))
    monkeypatch.setenv("WEALL_MEDIA_PROVIDER_URLS", "https://provider.example/ipfs/{cid}")

    def fake_urlopen(_req, timeout=0):  # noqa: ANN001
        return _BytesResponse(data)

    original_verify = media_routes._verify_cached_media_bytes

    def counting_verify(**kwargs):  # noqa: ANN003
        calls["verify"] += 1
        return original_verify(**kwargs)

    monkeypatch.setattr(media_routes.urllib.request, "urlopen", fake_urlopen)
    monkeypatch.setattr(media_routes, "_verify_cached_media_bytes", counting_verify)

    with _client(_state_with_media(cid, data)) as client:
        assert client.get(f"/v1/media/proxy/{cid}").status_code == 200
        assert calls["verify"] == 1
        # Metadata should avoid full reverify by default.
        assert client.get(f"/v1/media/proxy/{cid}", headers={"Range": "bytes=0-1"}).status_code == 206
        assert calls["verify"] == 1
        monkeypatch.setenv("WEALL_MEDIA_CACHE_STRICT_REVERIFY", "1")
        assert client.get(f"/v1/media/proxy/{cid}", headers={"Range": "bytes=2-3"}).status_code == 206
        assert calls["verify"] == 2


def test_peer_committed_block_fetch_sends_raw_read_token_batch370(monkeypatch, tmp_path: Path) -> None:
    from weall.net import net_loop
    from weall.net.net_loop import NetLoopConfig, NetMeshLoop

    captured: dict[str, Any] = {}

    def fake_urlopen(req, timeout=0):  # noqa: ANN001
        captured["url"] = req.full_url
        captured["headers"] = dict(req.header_items())
        return _JsonResponse({"ok": True, "block": {"block_id": "block:1", "height": 1}})

    monkeypatch.setenv("WEALL_PEER_STATE_RAW_READ_TOKEN", "peer-raw-token")
    monkeypatch.setenv("WEALL_PEERS_FILE", str(tmp_path / "peers.json"))
    monkeypatch.setattr(net_loop.urllib.request, "urlopen", fake_urlopen)

    loop = NetMeshLoop(
        executor=object(),
        mempool=object(),
        cfg=NetLoopConfig(enabled=False, bind_host="127.0.0.1", bind_port=0, tick_ms=25, schema_version="1"),
    )
    block = loop._fetch_committed_block("https://peer.example", "block:1")
    assert block == {"block_id": "block:1", "height": 1}
    assert captured["url"] == "https://peer.example/v1/state/block/block:1"
    assert captured["headers"]["X-weall-state-raw-read-token"] == "peer-raw-token"
    assert captured["headers"]["X-weall-state-sync-operator-token"] == "peer-raw-token"


def test_prod_sync_apply_requires_operator_token_when_enabled_batch370(monkeypatch) -> None:
    monkeypatch.setenv("WEALL_MODE", "prod")
    monkeypatch.setenv("WEALL_ENABLE_DEVNET_SYNC_APPLY_ROUTE", "1")
    monkeypatch.setenv("WEALL_STATE_SYNC_OPERATOR_TOKEN", "apply-secret")

    with _client() as client:
        missing = client.post("/v1/sync/apply", json={"response": {}})
        assert missing.status_code == 403, missing.text
        assert missing.json()["detail"]["code"] == "forbidden"

        bad = client.post(
            "/v1/sync/apply",
            json={"response": {}},
            headers={"X-WeAll-State-Sync-Operator-Token": "wrong"},
        )
        assert bad.status_code == 403, bad.text
        assert bad.json()["detail"]["code"] == "forbidden"

        authed = client.post(
            "/v1/sync/apply",
            json={"response": {}},
            headers={"X-WeAll-State-Sync-Operator-Token": "apply-secret"},
        )
        # Auth passed; the deliberately incomplete body now fails at sync-response validation.
        assert authed.status_code == 400, authed.text
        assert authed.json()["detail"]["code"] == "bad_sync_response"


def test_media_upload_docstring_discloses_ipfs_adapter_buffering_batch370() -> None:
    root = Path(__file__).resolve().parents[1]
    text = (root / "src" / "weall" / "api" / "routes_public_parts" / "media.py").read_text(encoding="utf-8")
    assert "sha256 calculation is streaming/bounded" in text
    assert "IPFS HTTP" in text and "buffer" in text
