from __future__ import annotations

from fastapi.testclient import TestClient

from weall.api.app import create_app


class _FakePool:
    def size(self) -> int:
        return 0


class _FakeExecutor:
    def __init__(self) -> None:
        self.node_id = "@fake-node"
        self.mempool = _FakePool()
        self.attestation_pool = _FakePool()

        self.block_loop_running = None
        self.block_loop_unhealthy = None
        self.block_loop_last_error = None
        self.block_loop_consecutive_failures = None

    def read_state(self) -> dict[str, object]:
        return {
            "chain_id": "readyz-test",
            "height": 7,
            "tip": "7:test-tip",
            "accounts": {},
            "blocks": {},
            "params": {},
            "poh": {},
            "roles": {},
        }

    def snapshot(self) -> dict[str, object]:
        return self.read_state()

    def tx_index_hash(self) -> str:
        return "abc123txindexhash"


def test_readyz_exposes_block_loop_signal_shape() -> None:
    """
    /v1/readyz should always expose a stable block_loop shape so operators
    can monitor producer health without guessing field presence.
    """
    app = create_app(boot_runtime=False)
    app.state.executor = _FakeExecutor()
    client = TestClient(app)

    r = client.get("/v1/readyz")
    assert r.status_code == 200

    body = r.json()
    assert body["ok"] is True

    assert "service" in body
    assert "version" in body
    assert "chain_id" in body
    assert "height" in body
    assert "tip" in body
    assert "tx_index_hash" in body
    assert "require_block_loop" in body
    assert "block_loop" in body

    block_loop = body["block_loop"]
    assert isinstance(block_loop, dict)

    assert set(block_loop.keys()) >= {
        "running",
        "unhealthy",
        "last_error",
        "consecutive_failures",
    }


def test_readyz_reflects_injected_block_loop_state() -> None:
    """
    If the executor has block-loop health metadata, /v1/readyz should surface it.
    """
    app = create_app(boot_runtime=False)
    ex = _FakeExecutor()
    ex.block_loop_running = True
    ex.block_loop_unhealthy = True
    ex.block_loop_last_error = "forced_test_failure"
    ex.block_loop_consecutive_failures = 3

    app.state.executor = ex

    client = TestClient(app)
    r = client.get("/v1/readyz")
    assert r.status_code == 200

    body = r.json()

    # Current implementation only reports ok=true when chain_id + tx_index_hash exist.
    assert body["ok"] is True

    block_loop = body["block_loop"]
    assert block_loop["running"] is True
    assert block_loop["unhealthy"] is True
    assert block_loop["last_error"] == "forced_test_failure"
    assert int(block_loop["consecutive_failures"]) == 3
