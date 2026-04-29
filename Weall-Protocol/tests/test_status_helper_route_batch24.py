from __future__ import annotations

from fastapi import FastAPI
from fastapi.testclient import TestClient

from weall.api.routes_public_parts.status import router
from weall.runtime.helper_release_gate import build_helper_release_gate_report


class _FakeExecutor:
    def snapshot(self):
        return {
            "chain_id": "weall",
            "node_id": "node-1",
            "height": 77,
            "tip": "tip-77",
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


def _client(report=None):
    app = FastAPI()
    app.include_router(router)
    app.state.executor = _FakeExecutor()
    app.state.helper_release_gate_report = report
    return TestClient(app)


def test_status_route_includes_helper_serial_only_batch24(monkeypatch):
    monkeypatch.delenv("WEALL_HELPER_MODE_ENABLED", raising=False)
    client = _client(None)
    resp = client.get("/status")
    assert resp.status_code == 200
    data = resp.json()
    assert data["chain_id"] == "weall"
    assert data["height"] == 77
    assert data["helper"]["helper_status"] == "serial_only"
    assert data["helper"]["helper_severity"] == "warning"


def test_status_route_includes_helper_enabled_batch24(monkeypatch):
    monkeypatch.setenv("WEALL_HELPER_MODE_ENABLED", "1")
    client = _client(_green_report())
    resp = client.get("/status")
    assert resp.status_code == 200
    data = resp.json()
    assert data["helper"]["helper_status"] == "helper_enabled"
    assert data["helper"]["helper_severity"] == "info"
    assert data["helper"]["helper_startup"]["helper_mode_active"] is True


def test_status_operator_route_surfaces_blocked_helper_batch24(monkeypatch):
    monkeypatch.setenv("WEALL_HELPER_MODE_ENABLED", "1")
    client = _client(_red_report())
    resp = client.get("/status/operator")
    assert resp.status_code == 200
    data = resp.json()
    assert data["operator_view"] is True
    assert data["operator"]["helper_status"] == "blocked"
    assert data["operator"]["helper_severity"] == "error"
    assert data["operator"]["helper_summary"] == "startup blocked: helper_release_gate_failed"


def test_status_operator_route_surfaces_enabled_helper_batch24(monkeypatch):
    monkeypatch.setenv("WEALL_HELPER_MODE_ENABLED", "1")
    client = _client(_green_report())
    resp = client.get("/status/operator")
    assert resp.status_code == 200
    data = resp.json()
    assert data["operator"]["helper_status"] == "helper_enabled"
    assert data["operator"]["helper_severity"] == "info"
