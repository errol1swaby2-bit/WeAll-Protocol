from __future__ import annotations

from fastapi.testclient import TestClient

from weall.api.app import create_app


class _StubExecutor:
    def __init__(self) -> None:
        self._state = {"system_queue": []}

    def snapshot(self):
        return self._state

    def enqueue_system_tx(self, tx):
        self._state.setdefault("system_queue", []).append(dict(tx))
        return str(tx.get("tx_id") or "stub-tx-id")


def test_operator_tier3_init_enqueues_canonical_system_tx_type(monkeypatch) -> None:
    monkeypatch.setenv("WEALL_ENABLE_OPERATOR_POH", "1")
    monkeypatch.setenv("WEALL_OPERATOR_TOKEN", "dev-operator-token")

    app = create_app(boot_runtime=False)
    app.state.executor = _StubExecutor()
    client = TestClient(app)

    response = client.post(
        "/v1/poh/operator/tier3/init",
        json={"case_id": "case-123", "join_url": "https://example.com/join"},
        headers={"X-WeAll-Operator-Token": "dev-operator-token"},
    )
    assert response.status_code == 200, response.text

    executor = app.state.executor
    state = executor.snapshot()
    queue = list(state.get("system_queue") or [])
    assert queue, "expected system tx to be enqueued"
    assert str(queue[-1].get("tx_type") or "") == "POH_TIER3_INIT"
