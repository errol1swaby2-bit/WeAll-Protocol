from __future__ import annotations

from fastapi.testclient import TestClient

from weall.api.app import create_app


class _StubExecutor:
    def __init__(self) -> None:
        self._state = {
            "height": 0,
            "poh": {
                "live_cases": {
                    "case-123": {
                        "case_id": "case-123",
                        "account_id": "acct-123",
                        "status": "requested",
                        "session_commitment": "session-commitment-123",
                        "room_commitment": "room-commitment-123",
                        "prompt_commitment": "prompt-commitment-123",
                    }
                }
            },
            "system_queue": [],
        }

    def snapshot(self):
        return self._state

    def enqueue_system_tx(self, tx):
        self._state.setdefault("system_queue", []).append(dict(tx))
        return str(tx.get("tx_id") or "stub-tx-id")


def test_operator_live_init_enqueues_canonical_system_tx_type(monkeypatch) -> None:
    monkeypatch.setenv("WEALL_ENABLE_OPERATOR_POH", "1")
    monkeypatch.setenv("WEALL_OPERATOR_TOKEN", "dev-operator-token")

    app = create_app(boot_runtime=False)
    app.state.executor = _StubExecutor()
    client = TestClient(app)

    response = client.post(
        "/v1/poh/operator/live/init",
        json={"case_id": "case-123", "join_url": "https://example.com/join"},
        headers={"X-WeAll-Operator-Token": "dev-operator-token"},
    )
    assert response.status_code == 200, response.text

    executor = app.state.executor
    state = executor.snapshot()
    queue = list(state.get("system_queue") or [])
    assert queue, "expected system tx to be enqueued"
    assert str(queue[-1].get("tx_type") or "") == "POH_LIVE_SESSION_INIT"
    payload = queue[-1].get("payload") or {}
    assert payload["case_id"] == "case-123"
    assert payload["account_id"] == "acct-123"
    assert payload["session_commitment"] == "session-commitment-123"
    assert payload.get("relay_commitment")
    assert "join_url" not in payload
