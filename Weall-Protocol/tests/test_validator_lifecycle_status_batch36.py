from __future__ import annotations

from fastapi.testclient import TestClient

from weall.api.app import create_app


class _FakePool:
    def __init__(self, n: int = 0) -> None:
        self._n = int(n)

    def size(self) -> int:
        return self._n


class _FakeExecutor:
    def __init__(self) -> None:
        self.node_id = "node-candidate"
        self.mempool = _FakePool(0)
        self.attestation_pool = _FakePool(0)
        self.block_loop_running = True
        self.block_loop_unhealthy = False
        self.block_loop_last_error = ""
        self.block_loop_consecutive_failures = 0
        self._schema_version_cached = "1"

    def read_state(self) -> dict[str, object]:
        return {
            "chain_id": "weall-dev",
            "height": 12,
            "tip": "12:block",
            "meta": {"schema_version": "1", "tx_index_hash": "txhash"},
            "roles": {"validators": {"active_set": ["@genesis"]}},
            "validators": {
                "registry": {
                    "@candidate": {
                        "account": "@candidate",
                        "pubkey": "ed25519:candidate",
                        "node_id": "node-candidate",
                        "status": "pending_activation",
                        "requested_activation_epoch": 2,
                        "approved_activation_epoch": 3,
                        "effective_epoch": 3,
                        "metadata_hash": "meta:candidate",
                    },
                    "@removed": {
                        "account": "@removed",
                        "pubkey": "ed25519:removed",
                        "node_id": "node-removed",
                        "status": "removed",
                    },
                }
            },
            "consensus": {
                "epochs": {"current": 2},
                "validator_set": {
                    "epoch": 2,
                    "set_hash": "sethash-2",
                    "active_set": ["@genesis"],
                    "pending": {"active_set": ["@genesis", "@candidate"], "activate_at_epoch": 3},
                },
            },
        }

    def snapshot(self) -> dict[str, object]:
        return self.read_state()

    def tx_index_hash(self) -> str:
        return "txhash"

    def bft_diagnostics(self) -> dict[str, object]:
        return {"view": 4, "stalled": False, "stall_reason": "idle", "protocol_profile_hash": "pfh", "schema_version": "1", "tx_index_hash": "txhash"}

    def validator_signing_enabled(self) -> bool:
        return False

    def _effective_signing_block_reason(self) -> str:
        return "validator pending activation at epoch 3"

    def _current_validator_epoch(self) -> int:
        return 2

    def _current_validator_set_hash(self) -> str:
        return "sethash-2"


def test_status_operator_surfaces_pending_validator_lifecycle(monkeypatch) -> None:
    monkeypatch.setenv("WEALL_MODE", "prod")
    monkeypatch.setenv("WEALL_VALIDATOR_ACCOUNT", "@candidate")

    app = create_app(boot_runtime=False)
    app.state.executor = _FakeExecutor()
    client = TestClient(app)

    body = client.get("/v1/status/operator").json()
    op = body["operator"]
    assert op["validator_lifecycle_state"] == "pending_activation"
    assert op["local_validator_record_found"] is True
    assert op["local_validator_is_pending"] is True
    assert op["local_validator_is_active"] is False
    assert op["pending_activation_epoch"] == 3
    assert op["current_validator_epoch"] == 2
    assert op["current_validator_set_hash"] == "sethash-2"
    assert op["signing_allowed_by_consensus_state"] is False
    assert op["signing_block_reason"] == "validator pending activation at epoch 3"


def test_status_consensus_surfaces_removed_validator_lifecycle(monkeypatch) -> None:
    monkeypatch.setenv("WEALL_MODE", "prod")
    monkeypatch.setenv("WEALL_VALIDATOR_ACCOUNT", "@removed")

    app = create_app(boot_runtime=False)
    app.state.executor = _FakeExecutor()
    client = TestClient(app)

    body = client.get("/v1/status/consensus").json()
    assert body["validator_lifecycle_state"] == "removed"
    assert body["local_validator_is_removed"] is True
    assert body["local_validator_is_active"] is False
    assert body["local_is_active_validator"] is False
