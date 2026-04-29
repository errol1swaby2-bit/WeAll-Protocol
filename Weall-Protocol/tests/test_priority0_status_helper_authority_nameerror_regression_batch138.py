from __future__ import annotations

from fastapi import FastAPI
from fastapi.testclient import TestClient

from weall.api.routes_public_parts.helper_readiness import router as helper_readiness_router
from weall.api.routes_public_parts.status import router as status_router
from weall.runtime.helper_release_gate import build_helper_release_gate_report


class _FakeExecutor:
    def __init__(self) -> None:
        self.node_id = "node-1"

    def read_state(self):
        return {
            "chain_id": "chain-b138",
            "height": 3,
            "tip": "abc123",
            "roles": {"validators": {"active_set": ["@validator-1"]}},
            "meta": {
                "schema_version": "1",
                "tx_index_hash": "txindex",
                "node_lifecycle": {
                    "requested_state": "production_service",
                    "effective_state": "bootstrap_registration",
                    "helper_enabled_requested": True,
                    "helper_enabled_effective": False,
                    "bft_enabled_requested": True,
                    "bft_enabled_effective": False,
                    "service_roles_requested": ["validator"],
                    "service_roles_effective": [],
                    "startup_action": "allow",
                    "promotion_failure_reasons": ["needs_promotion"],
                },
            },
        }

    snapshot = read_state

    def node_lifecycle_status(self):
        return self.read_state()["meta"]["node_lifecycle"]

    def bft_diagnostics(self):
        return {}

    def helper_execution_diagnostics(self):
        return {}

    def helper_reputation_diagnostics(self):
        return {}

    def transition_guardrail_diagnostics(self):
        return {}

    def mempool_selection_diagnostics(self, preview_limit: int = 0):
        return {}

    def validator_signing_enabled(self):
        return False


def test_status_operator_no_nameerror_and_helper_blocked_batch138(monkeypatch) -> None:
    monkeypatch.setenv("WEALL_HELPER_MODE_ENABLED", "1")

    app = FastAPI()
    app.include_router(status_router)
    app.include_router(helper_readiness_router)
    app.state.executor = _FakeExecutor()
    app.state.helper_release_gate_report = build_helper_release_gate_report(
        deterministic_replay_ok=False,
        timeout_fallback_ok=False,
        conflicting_replay_ok=False,
        restart_recovery_ok=False,
        merge_admission_ok=False,
        fail_closed_ok=False,
        serial_degrade_ok=False,
        soak_ok=False,
    )

    client = TestClient(app)

    operator = client.get("/status/operator")
    assert operator.status_code == 200
    body = operator.json()
    assert body["helper"]["helper_status"] == "blocked"
    assert body["operator"]["authority_contract"]["helper_requested"] is True
    assert body["operator"]["authority_contract"]["helper_effective"] is False

    readiness = client.get("/status/helper/readiness")
    assert readiness.status_code == 200
    ready = readiness.json()
    assert ready["overall_status"] == "blocked"
