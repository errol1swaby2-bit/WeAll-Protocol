from __future__ import annotations

from fastapi import FastAPI
from fastapi.testclient import TestClient

from weall.api.routes_public_parts.health import router
from weall.runtime.helper_release_gate import build_helper_release_gate_report


class _FakeExecutor:
    block_loop_running = True
    block_loop_unhealthy = False
    block_loop_last_error = None
    block_loop_consecutive_failures = 0

    def snapshot(self):
        return {
            "chain_id": "weall",
            "node_id": "node-1",
            "height": 42,
            "tip": "abc123",
        }

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


def _green_report():
    return build_helper_release_gate_report(
        deterministic_replay_ok=True,
        timeout_fallback_ok=True,
        conflicting_replay_ok=True,
        restart_recovery_ok=True,
        merge_admission_ok=True,
        fail_closed_ok=True,
        serial_degrade_ok=True,
        soak_ok=True,
    )


def _red_report():
    return build_helper_release_gate_report(
        deterministic_replay_ok=True,
        timeout_fallback_ok=True,
        conflicting_replay_ok=True,
        restart_recovery_ok=True,
        merge_admission_ok=False,
        fail_closed_ok=True,
        serial_degrade_ok=True,
        soak_ok=True,
    )


def _client(helper_requested: bool, report=None):
    app = FastAPI()
    app.include_router(router)
    app.state.executor = _FakeExecutor()
    app.state.helper_release_gate_report = report
    client = TestClient(app)
    client.headers.update({})
    return client


def test_health_route_includes_helper_surface_serial_only_batch23(monkeypatch):
    monkeypatch.delenv("WEALL_HELPER_MODE_ENABLED", raising=False)
    client = _client(helper_requested=False, report=None)
    resp = client.get("/health")
    assert resp.status_code == 200
    data = resp.json()
    assert data["helper"]["helper_status"] == "serial_only"
    assert data["helper"]["helper_severity"] == "warning"


def test_health_route_includes_helper_surface_enabled_batch23(monkeypatch):
    monkeypatch.setenv("WEALL_HELPER_MODE_ENABLED", "1")
    client = _client(helper_requested=True, report=_green_report())
    resp = client.get("/health")
    assert resp.status_code == 200
    data = resp.json()
    assert data["helper"]["helper_status"] == "helper_enabled"
    assert data["helper"]["helper_severity"] == "info"
    assert data["helper"]["helper_startup"]["helper_mode_active"] is True


def test_readyz_route_reflects_helper_blocked_batch23(monkeypatch):
    monkeypatch.setenv("WEALL_HELPER_MODE_ENABLED", "1")
    client = _client(helper_requested=True, report=_red_report())
    resp = client.get("/readyz")
    assert resp.status_code == 200
    data = resp.json()
    assert data["ok"] is False
    assert data["helper_status"] == "blocked"
    assert data["helper_severity"] == "error"


def test_readyz_route_stays_ready_with_helper_enabled_batch23(monkeypatch):
    monkeypatch.setenv("WEALL_HELPER_MODE_ENABLED", "1")
    client = _client(helper_requested=True, report=_green_report())
    resp = client.get("/readyz")
    assert resp.status_code == 200
    data = resp.json()
    assert data["ok"] is True
    assert data["helper_status"] == "helper_enabled"
    assert data["helper_severity"] == "info"
