from __future__ import annotations

from fastapi import FastAPI
from fastapi.testclient import TestClient

from weall.api.routes_public_parts.helper_readiness import router


class _FakeExecutor:
    def node_lifecycle_status(self):
        return {
            "requested_state": "bootstrap_registration",
            "effective_state": "bootstrap_registration",
            "helper_enabled_requested": False,
            "helper_enabled_effective": False,
            "bft_enabled_requested": False,
            "bft_enabled_effective": False,
            "service_roles_requested": [],
            "service_roles_effective": [],
            "startup_action": "allow",
            "promotion_failure_reasons": [],
        }

    def snapshot(self):
        return {"chain_id": "weall", "node_id": "node-1", "height": 1, "tip": "tip-1"}


def test_helper_readiness_prefers_app_startup_authority_contract_batch130(monkeypatch):
    monkeypatch.setenv("WEALL_MODE", "prod")
    monkeypatch.setenv("WEALL_HELPER_MODE_ENABLED", "1")
    app = FastAPI()
    app.include_router(router)
    app.state.executor = _FakeExecutor()
    app.state.helper_release_gate_report = None
    app.state.startup_authority_contract = {
        "strict_runtime_authority_mode": True,
        "requested_state": "production_service",
        "effective_state": "maintenance_restricted",
        "requested_roles": ["helper"],
        "effective_roles": [],
        "validator_requested": False,
        "validator_effective": False,
        "helper_requested": True,
        "helper_effective": False,
        "bft_requested": False,
        "bft_effective": False,
        "startup_action": "maintenance_restricted",
        "promotion_failure_reasons": ["ROLE_NOT_ACTIVE"],
    }
    body = TestClient(app).get("/status/helper/readiness").json()
    assert body["authority_contract_source"] == "app_startup"
    assert body["authority_contract"]["requested_state"] == "production_service"
    assert body["authority_contract"]["promotion_failure_reasons"] == ["ROLE_NOT_ACTIVE"]
