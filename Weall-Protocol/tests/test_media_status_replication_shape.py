from __future__ import annotations

from fastapi.testclient import TestClient

from weall.api.app import create_app


class _FakePool:
    def size(self) -> int:
        return 0

    def peek(self, limit: int = 50):
        return []


class _FakeExecutor:
    def __init__(self, state: dict[str, object]) -> None:
        self.node_id = "@fake-node"
        self.mempool = _FakePool()
        self.attestation_pool = _FakePool()
        self._state = state

    def read_state(self) -> dict[str, object]:
        return self._state

    def snapshot(self) -> dict[str, object]:
        return self._state

    def tx_index_hash(self) -> str:
        return "txindexhash-media-status"


def test_media_status_reports_replication_fields() -> None:
    """
    /v1/media/status/{cid} should expose the replication-oriented durability shape.
    """
    cid = "QmYwAPJzv5CZsnAzt8auVZRnGzr1rRkNvztNFVQVw1Gc7Y"
    state = {
        "chain_id": "media-status",
        "height": 10,
        "tip": "10:test-tip",
        "accounts": {},
        "blocks": {},
        "params": {"ipfs_replication_factor": 2},
        "poh": {},
        "roles": {},
        "storage": {
            "pins": {
                "pin1": {"cid": cid},
            },
            "pin_confirms": [
                {
                    "cid": cid,
                    "ok": True,
                    "operator_id": "@op1",
                    "at_nonce": 5,
                    "at_height": 8,
                },
                {
                    "cid": cid,
                    "ok": True,
                    "operator_id": "@op2",
                    "at_nonce": 6,
                    "at_height": 9,
                },
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
    assert int(body["replication_factor"]) == 2
    assert body["pin_requested"] is True
    assert int(body["ok_unique_ops"]) == 2
    assert body["durable"] is True

    assert "ok_total" in body
    assert "fail_total" in body
    assert "last_confirm_nonce" in body
    assert "last_confirm_height" in body

    assert int(body["ok_total"]) == 2
    assert int(body["fail_total"]) == 0
    assert int(body["last_confirm_nonce"]) == 6
    assert int(body["last_confirm_height"]) == 9


def test_media_status_not_yet_durable_when_replication_below_target() -> None:
    """
    Durability should remain false until unique successful operators reaches RF.
    """
    cid = "QmYwAPJzv5CZsnAzt8auVZRnGzr1rRkNvztNFVQVw1Gc7Y"
    state = {
        "chain_id": "media-status",
        "height": 10,
        "tip": "10:test-tip",
        "accounts": {},
        "blocks": {},
        "params": {"ipfs_replication_factor": 3},
        "poh": {},
        "roles": {},
        "storage": {
            "pins": {
                "pin1": {"cid": cid},
            },
            "pin_confirms": [
                {
                    "cid": cid,
                    "ok": True,
                    "operator_id": "@op1",
                    "at_nonce": 5,
                    "at_height": 8,
                },
                {
                    "cid": cid,
                    "ok": True,
                    "operator_id": "@op2",
                    "at_nonce": 6,
                    "at_height": 9,
                },
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
    assert int(body["replication_factor"]) == 3
    assert int(body["ok_unique_ops"]) == 2
    assert body["durable"] is False
    assert int(body["last_confirm_nonce"]) == 6
    assert int(body["last_confirm_height"]) == 9
