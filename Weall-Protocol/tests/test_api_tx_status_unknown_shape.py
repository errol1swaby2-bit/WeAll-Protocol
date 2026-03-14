from __future__ import annotations

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
            "chain_id": "api-tx-status-unknown",
            "height": 0,
            "tip": "",
            "accounts": {},
            "blocks": {},
            "params": {},
            "poh": {},
            "roles": {},
        }

    def snapshot(self) -> dict[str, object]:
        return self.read_state()

    def tx_index_hash(self) -> str:
        return "txindexhash-unknown-shape"

    def get_tx_status(self, tx_id: str) -> dict[str, object]:
        return {
            "ok": True,
            "tx_id": tx_id,
            "status": "unknown",
        }


def test_api_tx_status_unknown_shape_is_stable() -> None:
    """
    API should return a stable minimal shape for unknown tx ids.
    """
    app = create_app(boot_runtime=False)
    app.state.executor = _FakeExecutor()
    client = TestClient(app)

    r = client.get("/v1/tx/status/tx:does_not_exist")
    assert r.status_code == 200

    body = r.json()
    assert body["ok"] is True
    assert body["tx_id"] == "tx:does_not_exist"
    assert body["status"] == "unknown"
