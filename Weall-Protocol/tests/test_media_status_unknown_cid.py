from __future__ import annotations

from fastapi.testclient import TestClient

from weall.api.app import create_app


class _FakeExecutor:
    def read_state(self):
        return {
            "chain_id": "media-test",
            "height": 0,
            "tip": "",
            "accounts": {},
            "blocks": {},
            "params": {"ipfs_replication_factor": 2},
            "poh": {},
            "roles": {},
            "storage": {"pins": {}, "pin_confirms": []},
        }

    def snapshot(self):
        return self.read_state()

    def tx_index_hash(self):
        return "test"


def test_media_status_unknown_cid():
    """
    Querying an unknown but valid CID should still return a stable response shape.
    """

    cid = "QmYwAPJzv5CZsnAzt8auVZRnGzr1rRkNvztNFVQVw1Gc7Y"

    app = create_app(boot_runtime=False)
    app.state.executor = _FakeExecutor()

    client = TestClient(app)

    r = client.get(f"/v1/media/status/{cid}")
    assert r.status_code == 200

    body = r.json()

    assert body["cid"] == cid
    assert body["durable"] is False
    assert body["pin_requested"] is False
