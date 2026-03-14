from __future__ import annotations

from fastapi.testclient import TestClient

from weall.api.app import create_app


class _FakeExecutor:
    def __init__(self, state: dict) -> None:
        self._state = state

    def snapshot(self) -> dict:
        return self._state


def test_media_status_survives_restore_shape() -> None:
    """
    /v1/media/status/{cid} should keep the same stable response shape after a
    restored snapshot is mounted into the app.

    Use a known-valid CID so this test exercises the restore/status shape path,
    not CID-validation failure behavior.
    """
    cid = "QmYwAPJzv5CZsnAzt8auVZRnGzr1rRkNvztNFVQVw1Gc7Y"

    state = {
        "chain_id": "restore-media-shape",
        "height": 12,
        "tip": "12:test-tip",
        "accounts": {},
        "blocks": {},
        "params": {"ipfs_replication_factor": 2},
        "poh": {},
        "roles": {},
        "storage": {
            "pins": {"pin1": {"cid": cid}},
            "pin_confirms": [
                {
                    "cid": cid,
                    "ok": True,
                    "operator_id": "@op1",
                    "at_nonce": 10,
                    "at_height": 11,
                }
            ],
        },
    }

    app = create_app(boot_runtime=False)
    app.state.executor = _FakeExecutor(state)
    client = TestClient(app)

    r = client.get(f"/v1/media/status/{cid}")
    assert r.status_code == 200

    body = r.json()
    assert body["ok"] is True
    assert body["cid"] == cid
    assert "replication_factor" in body
    assert "pin_requested" in body
    assert "ok_unique_ops" in body
    assert "ok_total" in body
    assert "fail_total" in body
    assert "last_confirm_height" in body
    assert "durable" in body
