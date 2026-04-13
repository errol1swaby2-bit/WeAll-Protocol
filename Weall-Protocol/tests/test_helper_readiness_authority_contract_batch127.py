from __future__ import annotations

from fastapi import FastAPI
from fastapi.testclient import TestClient

from weall.api.routes_public_parts.helper_readiness import router


class _FakeExecutor:
    def __init__(self, lifecycle: dict[str, object]):
        self._lifecycle = lifecycle

    def snapshot(self):
        return {"chain_id": "weall", "node_id": "node-1", "height": 1, "tip": "tip-1"}

    def node_lifecycle_status(self):
        return dict(self._lifecycle)


def _client(lifecycle: dict[str, object]):
    app = FastAPI()
    app.include_router(router)
    app.state.executor = _FakeExecutor(lifecycle)
    app.state.helper_release_gate_report = None
    return TestClient(app)


def test_helper_readiness_surfaces_authority_contract_batch127(monkeypatch):
    monkeypatch.setenv("WEALL_MODE", "prod")
    monkeypatch.setenv("WEALL_NODE_LIFECYCLE_STATE", "production_service")
    monkeypatch.setenv("WEALL_HELPER_MODE_ENABLED", "1")
    lifecycle = {
        "requested_state": "production_service",
        "effective_state": "maintenance_restricted",
        "helper_enabled_requested": True,
        "helper_enabled_effective": False,
        "bft_enabled_requested": False,
        "bft_enabled_effective": False,
        "service_roles_requested": ["helper"],
        "service_roles_effective": [],
        "startup_action": "maintenance_restricted",
        "promotion_failure_reasons": ["ROLE_NOT_ACTIVE"],
    }
    body = _client(lifecycle).get("/status/helper/readiness").json()
    assert body["helper_mode_requested"] is True
    assert body["helper_mode_effective"] is False
    contract = body["authority_contract"]
    assert contract["strict_runtime_authority_mode"] is True
    assert contract["helper_requested"] is True
    assert contract["helper_effective"] is False
    assert contract["promotion_failure_reasons"] == ["ROLE_NOT_ACTIVE"]
