from __future__ import annotations

from io import BytesIO

from fastapi.testclient import TestClient

from weall.api.app import create_app


class _FakePool:
    def size(self) -> int:
        return 0

    def peek(self, limit: int = 50):
        return []


class _FakeExecutor:
    def __init__(self, tier: int) -> None:
        self.node_id = "@fake-node"
        self.mempool = _FakePool()
        self.attestation_pool = _FakePool()
        self._tier = int(tier)

    def read_state(self) -> dict[str, object]:
        return {
            "chain_id": "media-tier-gate",
            "height": 1,
            "tip": "1:test-tip",
            "accounts": {
                "@user": {
                    "banned": False,
                    "locked": False,
                    "nonce": 1,
                    "poh_tier": self._tier,
                    "devices": {"by_id": {}},
                    "keys": {"by_id": {}},
                    "recovery": {"config": None, "proposals": {}},
                    "reputation": 0,
                    "session_keys": {"sess-ok": {"revoked": False}},
                }
            },
            "blocks": {},
            "params": {},
            "poh": {},
            "roles": {},
        }

    def snapshot(self) -> dict[str, object]:
        return self.read_state()

    def tx_index_hash(self) -> str:
        return "txindexhash-tier-gate"


def test_media_upload_rejects_non_tier3_user(monkeypatch) -> None:
    """
    Upload must remain hard-gated behind PoH tier 3+.
    """
    app = create_app(boot_runtime=False)
    app.state.executor = _FakeExecutor(tier=2)

    from weall.api.routes_public_parts import media as media_routes

    def _fake_require_account_session(request, st):
        return "@user"

    monkeypatch.setattr(media_routes, "require_account_session", _fake_require_account_session)

    client = TestClient(app)

    files = {
        "file": ("hello.txt", BytesIO(b"hello world"), "text/plain"),
    }
    r = client.post("/v1/media/upload", files=files)

    assert r.status_code == 403
    body = r.json()
    assert body["ok"] is False
    assert body["error"]["code"] == "forbidden"
    assert "tier 3" in body["error"]["message"].lower()


def test_media_upload_allows_tier3_user(monkeypatch) -> None:
    """
    Tier 3 users should be allowed through the gate if IPFS add succeeds.
    """
    app = create_app(boot_runtime=False)
    app.state.executor = _FakeExecutor(tier=3)

    from weall.api.routes_public_parts import media as media_routes

    def _fake_require_account_session(request, st):
        return "@user"

    def _fake_ipfs_add_fileobj(*, name: str, fileobj, pin: bool):
        return "QmYwAPJzv5CZsnAzt8auVZRnGzr1rRkNvztNFVQVw1Gc7Y", 11

    monkeypatch.setattr(media_routes, "require_account_session", _fake_require_account_session)
    monkeypatch.setattr(media_routes, "ipfs_add_fileobj", _fake_ipfs_add_fileobj)

    client = TestClient(app)

    files = {
        "file": ("hello.txt", BytesIO(b"hello world"), "text/plain"),
    }
    r = client.post("/v1/media/upload", files=files)

    assert r.status_code == 200
    body = r.json()
    assert body["ok"] is True
    assert body["cid"] == "QmYwAPJzv5CZsnAzt8auVZRnGzr1rRkNvztNFVQVw1Gc7Y"
    assert body["size"] == 11
