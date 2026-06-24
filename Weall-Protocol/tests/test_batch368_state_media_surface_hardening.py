from __future__ import annotations

import hashlib
from io import BytesIO
from pathlib import Path
from typing import Any

from fastapi.testclient import TestClient

from weall.api.app import create_app


class _FakePool:
    def size(self) -> int:
        return 0

    def peek(self, limit: int = 50):
        return []


class _FakeExecutor:
    node_id = "@fake-node"
    chain_id = "batch368-chain"
    mempool = _FakePool()
    attestation_pool = _FakePool()

    def __init__(self, state: dict[str, Any] | None = None) -> None:
        self._state = state or _state()

    def read_state(self) -> dict[str, Any]:
        return self._state

    def snapshot(self) -> dict[str, Any]:
        return self._state

    def tx_index_hash(self) -> str:
        return "txindexhash-batch368"

    def get_block_by_id(self, block_id: str) -> dict[str, Any] | None:
        return {
            "block_id": block_id,
            "height": 9,
            "parent": "block:8",
            "state_root": "root:9",
            "txs": [
                {
                    "tx_type": "CONTENT_POST_CREATE",
                    "payload": {
                        "post_id": "post:private",
                        "body": "private block body must not be public",
                        "visibility": "private",
                    },
                }
            ],
        }


def _state() -> dict[str, Any]:
    return {
        "chain_id": "batch368-chain",
        "height": 9,
        "accounts": {
            "@live": {
                "nonce": 3,
                "poh_tier": 2,
                "banned": False,
                "locked": False,
                "session_keys": {"sess-ok": {"revoked": False}},
                "devices": {"by_id": {}},
                "keys": {"by_id": {}},
            }
        },
        "groups": {
            "group:private": {
                "group_id": "group:private",
                "visibility": "private",
                "members": {"@live": {"status": "active"}},
            }
        },
        "content": {
            "posts": {
                "post:public": {
                    "post_id": "post:public",
                    "author": "@live",
                    "body": "public body",
                    "visibility": "public",
                    "created_nonce": 1,
                },
                "post:private": {
                    "post_id": "post:private",
                    "author": "@live",
                    "body": "private snapshot body must not leak",
                    "visibility": "private",
                    "created_nonce": 2,
                },
                "post:group": {
                    "post_id": "post:group",
                    "author": "@live",
                    "group_id": "group:private",
                    "body": "nonpublic group snapshot body must not leak",
                    "visibility": "group",
                    "created_nonce": 3,
                },
            },
            "comments": {
                "comment:private": {
                    "comment_id": "comment:private",
                    "post_id": "post:public",
                    "body": "private comment snapshot body must not leak",
                    "visibility": "private",
                    "created_nonce": 4,
                }
            },
            "media": {
                "media:private": {
                    "media_id": "media:private",
                    "payload": {"cid": "bafyprivate", "name": "private.png"},
                }
            },
        },
    }


def _client(state: dict[str, Any] | None = None) -> TestClient:
    app = create_app(boot_runtime=False)
    app.state.executor = _FakeExecutor(state)
    return TestClient(app, raise_server_exceptions=False)


def test_public_state_snapshot_prunes_content_and_group_maps_batch368() -> None:
    client = _client()
    res = client.get("/v1/state/snapshot")
    assert res.status_code == 200, res.text
    body = res.json()
    assert body["ok"] is True
    assert body["state"]["content"]["redacted"] is True
    assert body["state"]["groups"]["redacted"] is True
    assert "private snapshot body" not in res.text
    assert "nonpublic group snapshot body" not in res.text
    assert "private comment snapshot body" not in res.text
    assert "bafyprivate" not in res.text


def test_raw_block_fetch_is_operator_gated_in_prod_and_header_is_public_batch368(monkeypatch) -> None:
    monkeypatch.setenv("WEALL_MODE", "prod")
    monkeypatch.setenv("WEALL_STATE_RAW_READ_TOKEN", "raw-ok")
    client = _client()

    public_raw = client.get("/v1/state/block/block:9")
    assert public_raw.status_code == 403
    assert "private block body" not in public_raw.text

    header = client.get("/v1/state/block/block:9/header")
    assert header.status_code == 200, header.text
    header_body = header.json()["block"]
    assert header_body["block_id"] == "block:9"
    assert header_body["tx_count"] == 1
    assert "private block body" not in header.text

    authed = client.get("/v1/state/block/block:9", headers={"X-WeAll-State-Raw-Read-Token": "raw-ok"})
    assert authed.status_code == 200, authed.text
    assert "private block body" in authed.text


def test_sync_request_rejects_oversized_json_before_parsing_batch368(monkeypatch) -> None:
    monkeypatch.setenv("WEALL_MODE", "prod")
    monkeypatch.setenv("WEALL_ENABLE_STATE_SYNC_HTTP_REQUEST_ROUTE", "1")
    monkeypatch.setenv("WEALL_STATE_SYNC_OPERATOR_TOKEN", "sync-ok")
    monkeypatch.setenv("WEALL_STATE_SYNC_REQUEST_MAX_BYTES", "16")
    client = _client()

    res = client.post(
        "/v1/sync/request",
        data=b'{"mode":"delta","padding":"too-large"}',
        headers={"content-type": "application/json", "X-WeAll-State-Sync-Operator-Token": "sync-ok"},
    )
    assert res.status_code == 413, res.text
    assert res.json()["error"]["code"] == "payload_too_large"


def test_media_upload_returns_file_byte_sha256_for_declare_batch368(monkeypatch) -> None:
    from weall.api.routes_public_parts import media as media_routes

    payload = b"hello world"
    expected = hashlib.sha256(payload).hexdigest()

    def _fake_require_account_session(request, st):
        return "@live"

    def _fake_ipfs_add_fileobj(*, name: str, fileobj, pin: bool):
        # The upload route must rewind after hashing so IPFS still receives bytes.
        assert fileobj.read() == payload
        return "QmYwAPJzv5CZsnAzt8auVZRnGzr1rRkNvztNFVQVw1Gc7Y", len(payload)

    monkeypatch.setattr(media_routes, "require_account_session", _fake_require_account_session)
    monkeypatch.setattr(media_routes, "ipfs_add_fileobj", _fake_ipfs_add_fileobj)

    client = _client()
    res = client.post("/v1/media/upload", files={"file": ("hello.txt", BytesIO(payload), "text/plain")})
    assert res.status_code == 200, res.text
    body = res.json()
    assert body["ok"] is True
    assert body["sha256"] == expected
    assert body["content_sha256"] == expected
    assert body["media_declare_defaults"]["sha256"] == expected
    assert body["pin_request"]["envelope"]["payload"]["sha256"] == expected


def test_frontend_commits_upload_sha256_and_dispute_uses_scoped_content_batch368() -> None:
    root = Path(__file__).resolve().parents[2]
    create_post = (root / "web" / "src" / "pages" / "CreatePostPage.tsx").read_text(encoding="utf-8")
    api = (root / "web" / "src" / "api" / "weall.ts").read_text(encoding="utf-8")
    review = (root / "web" / "src" / "pages" / "DisputeReview.tsx").read_text(encoding="utf-8")

    assert "uploadSha256" in create_post
    assert "sha256: uploadSha256" in create_post
    assert "content_sha256: uploadSha256" in create_post
    assert "contentScoped(id:" in api
    assert "weall.contentScoped(targetId" in review
    assert "getAuthHeaders" in review
