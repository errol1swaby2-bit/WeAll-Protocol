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
    def __init__(self) -> None:
        self.node_id = "@fake-node"
        self.mempool = _FakePool()
        self.attestation_pool = _FakePool()

    def read_state(self) -> dict[str, object]:
        return {
            "chain_id": "media-test",
            "height": 1,
            "tip": "1:test-tip",
            "accounts": {
                "@tier3": {
                    "banned": False,
                    "locked": False,
                    "nonce": 3,
                    "poh_tier": 3,
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
        return "txindexhash-media"


def test_media_upload_fails_closed_when_ipfs_unavailable(monkeypatch) -> None:
    """
    If IPFS add fails, the API must fail closed with a structured ipfs_error
    rather than returning 200 or silently accepting the upload.
    """
    app = create_app(boot_runtime=False)
    app.state.executor = _FakeExecutor()

    from weall.api.routes_public_parts import media as media_routes

    def _fake_require_account_session(request, st):
        return "@tier3"

    def _fake_ipfs_add_fileobj(*, name: str, fileobj, pin: bool):
        raise RuntimeError("ipfs_add_failed:http_500:forced_test_failure")

    monkeypatch.setattr(media_routes, "require_account_session", _fake_require_account_session)
    monkeypatch.setattr(media_routes, "ipfs_add_fileobj", _fake_ipfs_add_fileobj)

    client = TestClient(app)

    files = {
        "file": ("hello.txt", BytesIO(b"hello world"), "text/plain"),
    }
    r = client.post("/v1/media/upload", files=files)

    assert r.status_code in {400, 503}
    body = r.json()
    assert body["ok"] is False
    assert body["error"]["code"] == "ipfs_error"
    assert "forced_test_failure" in body["error"]["message"]
