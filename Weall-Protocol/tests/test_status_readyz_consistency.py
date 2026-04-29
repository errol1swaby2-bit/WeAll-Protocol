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
            "chain_id": "status-readyz-test",
            "height": 12,
            "tip": "12:test-tip",
            "tip_hash": "tiphash123",
            "tip_ts_ms": 1234567890,
            "accounts": {},
            "blocks": {},
            "params": {},
            "poh": {},
            "roles": {},
        }

    def snapshot(self) -> dict[str, object]:
        return self.read_state()

    def tx_index_hash(self) -> str:
        return "txindexhash456"


def test_status_and_readyz_are_shape_consistent() -> None:
    """
    /v1/status and /v1/readyz should agree on core chain identity fields.
    """
    app = create_app(boot_runtime=False)
    app.state.executor = _FakeExecutor()
    client = TestClient(app)

    rs = client.get("/v1/status")
    rr = client.get("/v1/readyz")

    assert rs.status_code == 200
    assert rr.status_code == 200

    status = rs.json()
    readyz = rr.json()

    assert status["ok"] is True
    assert readyz["ok"] is True

    assert "chain_id" in status
    assert "chain_id" in readyz
    assert "height" in status
    assert "height" in readyz
    assert "tip" in status
    assert "tip" in readyz

    assert status["chain_id"] == readyz["chain_id"]
    assert int(status["height"]) == int(readyz["height"])
    assert str(status["tip"]) == str(readyz["tip"])


def test_readyz_exposes_tx_index_hash() -> None:
    """
    /v1/readyz should expose tx_index_hash for operator sanity checks.
    """
    app = create_app(boot_runtime=False)
    app.state.executor = _FakeExecutor()
    client = TestClient(app)

    r = client.get("/v1/readyz")
    assert r.status_code == 200

    body = r.json()
    assert body["ok"] is True

    assert "tx_index_hash" in body
    assert isinstance(body["tx_index_hash"], str)
    assert body["tx_index_hash"]
