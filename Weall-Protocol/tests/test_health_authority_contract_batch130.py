from __future__ import annotations

from fastapi import FastAPI
from fastapi.testclient import TestClient

from weall.api.routes_public_parts.health import router


class _FakeExecutor:
    block_loop_running = True
    block_loop_unhealthy = False
    block_loop_last_error = None
    block_loop_consecutive_failures = 0

    def snapshot(self):
        return {"chain_id": "weall", "node_id": "node-1", "height": 42, "tip": "abc123"}

    def tx_index_hash(self):
        return "tx-index-hash"

    def bft_diagnostics(self):
        return {
            "stalled": False,
            "stall_reason": "ok",
            "pending_remote_blocks_count": 0,
            "pending_candidates_count": 0,
            "pending_missing_qcs_count": 0,
            "pending_fetch_requests_count": 0,
            "pending_artifacts_pruned": False,
            "pacemaker_timeout_ms": 1000,
            "clock_skew_warning": False,
            "clock_skew_ahead_ms": 0,
            "protocol_profile_hash": "profile-hash",
            "reputation_scale": 1,
            "max_block_future_drift_ms": 120000,
            "clock_skew_warn_ms": 30000,
        }


def test_health_prefers_app_startup_authority_contract_batch130(monkeypatch):
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
    body = TestClient(app).get("/health").json()
    assert body["helper"]["authority_contract_source"] == "app_startup"
    assert body["helper"]["authority_contract"]["requested_state"] == "production_service"
    ready = TestClient(app).get("/readyz").json()
    assert ready["authority_contract_source"] == "app_startup"
    assert ready["authority_contract"]["helper_requested"] is True
