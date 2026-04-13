from __future__ import annotations

from types import SimpleNamespace

from fastapi import FastAPI
from fastapi.testclient import TestClient
import pytest

from weall.api.routes_public_parts.status import router as status_router


class _FakeExecutor(SimpleNamespace):
    def read_state(self):
        return {
            "chain_id": self.chain_id,
            "node_id": self.node_id,
            "height": 0,
            "tip": "",
            "meta": {
                "runtime_open": True,
                "last_shutdown_clean": True,
            },
        }


def _make_executor() -> _FakeExecutor:
    return _FakeExecutor(
        chain_id="weall-test",
        node_id="node-1",
        node_lifecycle_status=lambda: {
            "requested_state": "production_service",
            "effective_state": "maintenance_restricted",
            "service_roles_requested": ["validator"],
            "service_roles_effective": [],
            "helper_enabled_requested": False,
            "helper_enabled_effective": False,
            "bft_enabled_requested": True,
            "bft_enabled_effective": False,
            "startup_action": "maintenance_restricted",
            "promotion_preflight_passed": False,
            "promotion_failure_reasons": ["ROLE_NOT_ACTIVE"],
        },
    )


def _build_test_app(executor: _FakeExecutor) -> FastAPI:
    app = FastAPI()
    app.include_router(status_router, prefix="/v1")
    app.state.executor = executor
    app.state.startup_authority_contract = {
        "strict_runtime_authority_mode": True,
        "requested_state": "production_service",
        "effective_state": "maintenance_restricted",
        "requested_roles": ["validator"],
        "effective_roles": [],
        "validator_requested": True,
        "validator_effective": False,
        "helper_requested": False,
        "helper_effective": False,
        "bft_requested": True,
        "bft_effective": False,
        "startup_action": "app_state_override",
        "promotion_failure_reasons": ["FROM_APP_STATE"],
    }
    app.state.net = None
    app.state.net_node = None
    app.state.net_loop = None
    app.state.block_loop = None
    return app


def test_status_operator_prefers_app_startup_authority_contract_batch129(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("WEALL_MODE", "prod")
    monkeypatch.setenv("WEALL_CHAIN_ID", "weall-test")
    monkeypatch.setenv("WEALL_BFT_ENABLED", "1")
    monkeypatch.setenv("WEALL_NODE_LIFECYCLE_STATE", "production_service")
    monkeypatch.setenv("WEALL_SERVICE_ROLES", "validator")

    app = _build_test_app(_make_executor())
    client = TestClient(app)
    body = client.get("/v1/status/operator").json()

    startup_contract = body["operator"]["startup_posture"]["authority_contract"]
    operator_contract = body["operator"]["authority_contract"]
    assert startup_contract["contract_source"] == "app_startup"
    assert operator_contract["contract_source"] == "app_startup"
    assert startup_contract["promotion_failure_reasons"] == ["FROM_APP_STATE"]
    assert operator_contract["promotion_failure_reasons"] == ["FROM_APP_STATE"]
    assert startup_contract["startup_action"] == "app_state_override"
    assert operator_contract["startup_action"] == "app_state_override"


def test_status_consensus_prefers_app_startup_authority_contract_batch129(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("WEALL_MODE", "prod")
    monkeypatch.setenv("WEALL_CHAIN_ID", "weall-test")
    monkeypatch.setenv("WEALL_BFT_ENABLED", "1")
    monkeypatch.setenv("WEALL_NODE_LIFECYCLE_STATE", "production_service")
    monkeypatch.setenv("WEALL_SERVICE_ROLES", "validator")

    app = _build_test_app(_make_executor())
    client = TestClient(app)
    body = client.get("/v1/status/consensus").json()

    startup_contract = body["startup_posture"]["authority_contract"]
    assert startup_contract["contract_source"] == "app_startup"
    assert startup_contract["promotion_failure_reasons"] == ["FROM_APP_STATE"]
    assert startup_contract["validator_requested"] is True
    assert startup_contract["validator_effective"] is False
