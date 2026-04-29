from __future__ import annotations

from fastapi.testclient import TestClient

from weall.api.app import create_app


class _FakeExecutor:
    def __init__(self, state):
        self._state = state

    def read_state(self):
        return self._state

    def snapshot(self):
        return self._state

    def tx_index_hash(self):
        return "test"


def test_failed_confirmations_not_counted():
    """
    Failed pin confirmations must not contribute to durability.
    """

    cid = "QmYwAPJzv5CZsnAzt8auVZRnGzr1rRkNvztNFVQVw1Gc7Y"

    state = {
        "chain_id": "media-test",
        "height": 1,
        "tip": "1:test",
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
                    "ok": False,
                    "operator_id": "@op1",
                    "at_nonce": 1,
                    "at_height": 1,
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

    assert body["durable"] is False
    assert int(body["ok_unique_ops"]) == 0
    assert int(body["fail_total"]) == 1
