from __future__ import annotations

from fastapi.testclient import TestClient

from weall.api.app import create_app


class _CountingExecutor:
    def __init__(self) -> None:
        self.read_calls = 0
        self._state = {
            "chain_id": "p1-a15-snapshot",
            "height": 7,
            "accounts": {
                f"@user{i:05d}": {
                    "nonce": 1,
                    "poh_tier": 0,
                    "banned": False,
                    "locked": False,
                }
                for i in range(10_000)
            },
        }

    def read_state(self) -> dict:
        self.read_calls += 1
        return self._state


def _client(executor: _CountingExecutor) -> TestClient:
    app = create_app(boot_runtime=False)
    app.state.executor = executor
    return TestClient(app, raise_server_exceptions=False)


def test_a15_f005_prod_snapshot_authenticates_before_full_state_read(monkeypatch) -> None:
    monkeypatch.setenv("WEALL_MODE", "prod")
    monkeypatch.setenv("WEALL_STATE_RAW_READ_TOKEN", "snapshot-operator")
    monkeypatch.delenv("WEALL_STATE_RAW_READ_ALLOW_LOOPBACK_WITHOUT_TOKEN", raising=False)

    executor = _CountingExecutor()
    client = _client(executor)

    missing = client.get("/v1/state/snapshot")
    assert missing.status_code == 403
    assert executor.read_calls == 0

    bad = client.get(
        "/v1/state/snapshot",
        headers={"X-WeAll-State-Raw-Read-Token": "wrong"},
    )
    assert bad.status_code == 403
    assert executor.read_calls == 0

    allowed = client.get(
        "/v1/state/snapshot",
        headers={"X-WeAll-State-Raw-Read-Token": "snapshot-operator"},
    )
    assert allowed.status_code == 200, allowed.text
    assert allowed.json()["ok"] is True
    assert executor.read_calls == 1


def test_a15_f005_dev_snapshot_remains_available_without_operator_token(monkeypatch) -> None:
    monkeypatch.setenv("WEALL_MODE", "test")
    monkeypatch.delenv("WEALL_STATE_RAW_READ_TOKEN", raising=False)

    executor = _CountingExecutor()
    client = _client(executor)

    response = client.get("/v1/state/snapshot")
    assert response.status_code == 200, response.text
    assert executor.read_calls == 1
