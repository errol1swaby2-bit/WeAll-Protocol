from __future__ import annotations

from fastapi.testclient import TestClient

from weall.api.app import create_app


class _FakePool:
    def size(self) -> int:
        return 0


class _FakeExecutor:
    def __init__(self) -> None:
        self.node_id = "node-observer"
        self.mempool = _FakePool()
        self.attestation_pool = _FakePool()
        self.block_loop_running = True
        self.block_loop_unhealthy = False
        self.block_loop_last_error = ""
        self.block_loop_consecutive_failures = 0
        self._schema_version_cached = "1"

    def read_state(self) -> dict[str, object]:
        return {
            "chain_id": "weall-dev",
            "height": 5,
            "tip": "5:block",
            "meta": {"schema_version": "1", "tx_index_hash": "txhash"},
            "roles": {"validators": {"active_set": ["@genesis"]}},
            "validators": {"registry": {}},
            "consensus": {"epochs": {"current": 0}, "validator_set": {"epoch": 0, "set_hash": "genesis-hash", "active_set": ["@genesis"], "pending": {}}},
        }

    def snapshot(self) -> dict[str, object]:
        return self.read_state()

    def tx_index_hash(self) -> str:
        return "txhash"

    def validator_signing_enabled(self) -> bool:
        return False

    def _effective_signing_block_reason(self) -> str:
        return "validator not active in current epoch"

    def _current_validator_epoch(self) -> int:
        return 0

    def _current_validator_set_hash(self) -> str:
        return "genesis-hash"


def test_status_operator_defaults_unknown_validator_to_observer(monkeypatch) -> None:
    monkeypatch.setenv("WEALL_MODE", "prod")
    monkeypatch.setenv("WEALL_VALIDATOR_ACCOUNT", "@unknown")
    app = create_app(boot_runtime=False)
    app.state.executor = _FakeExecutor()
    client = TestClient(app)
    body = client.get("/v1/status/operator").json()
    op = body["operator"]
    assert op["validator_lifecycle_state"] == "observer"
    assert op["local_validator_record_found"] is False
    assert op["local_validator_is_active"] is False
    assert op["local_validator_is_pending"] is False
    assert op["current_validator_epoch"] == 0
    assert op["current_validator_set_hash"] == "genesis-hash"
