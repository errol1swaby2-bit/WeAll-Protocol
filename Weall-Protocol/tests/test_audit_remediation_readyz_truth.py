from __future__ import annotations

from fastapi.testclient import TestClient

from weall.api.app import create_app


class _Executor:
    block_loop_running = True
    block_loop_unhealthy = False
    block_loop_last_error = ""
    block_loop_consecutive_failures = 0

    def read_state(self) -> dict:
        return {"chain_id": "readyz-audit", "height": 1, "tip": "1:tip", "params": {}}

    def tx_index_hash(self) -> str:
        return "sha256:tx-index"


def _client(monkeypatch) -> tuple[TestClient, _Executor]:
    monkeypatch.setenv("WEALL_MODE", "prod")
    app = create_app(boot_runtime=False)
    executor = _Executor()
    app.state.executor = executor
    return TestClient(app), executor


def test_readyz_fails_when_block_loop_is_unhealthy(monkeypatch) -> None:
    client, executor = _client(monkeypatch)
    executor.block_loop_unhealthy = True
    body = client.get("/v1/readyz").json()
    assert body["ok"] is False
    assert body["block_loop"]["unhealthy"] is True


def test_readyz_fails_when_block_loop_is_explicitly_stopped(monkeypatch) -> None:
    client, executor = _client(monkeypatch)
    executor.block_loop_running = False
    body = client.get("/v1/readyz").json()
    assert body["ok"] is False
    assert body["block_loop"]["running"] is False
