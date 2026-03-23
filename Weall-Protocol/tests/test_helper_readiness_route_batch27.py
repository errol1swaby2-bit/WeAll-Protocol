from __future__ import annotations

from fastapi import FastAPI
from fastapi.testclient import TestClient

from weall.api.routes_public_parts.helper_readiness import router
from weall.runtime.helper_release_gate import build_helper_release_gate_report


class _FakeExecutor:
    def snapshot(self):
        return {
            "chain_id": "weall",
            "node_id": "node-1",
            "height": 88,
            "tip": "tip-88",
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


def test_helper_readiness_route_serial_only_batch27(monkeypatch):
    monkeypatch.delenv("WEALL_HELPER_MODE_ENABLED", raising=False)
    client = _client(None)
    r = client.get("/status/helper/readiness")
    assert r.status_code == 200
    body = r.json()
    assert body["chain_id"] == "weall"
    assert body["helper_mode_requested"] is False
    assert body["overall_status"] == "serial_only"
    assert body["startup"]["startup_mode"] == "serial_only"


def test_helper_readiness_route_ready_with_helpers_batch27(monkeypatch):
    monkeypatch.setenv("WEALL_HELPER_MODE_ENABLED", "1")
    client = _client(_green_report())
    r = client.get("/status/helper/readiness")
    assert r.status_code == 200
    body = r.json()
    assert body["helper_mode_requested"] is True
    assert body["overall_status"] == "ready"
    assert body["preflight"]["accepted"] is True
    assert body["release_gate"]["readiness_score"] == 100


def test_helper_readiness_route_blocked_batch27(monkeypatch):
    monkeypatch.setenv("WEALL_HELPER_MODE_ENABLED", "1")
    client = _client(_red_report())
    r = client.get("/status/helper/readiness")
    assert r.status_code == 200
    body = r.json()
    assert body["helper_mode_requested"] is True
    assert body["overall_status"] == "blocked"
    assert body["overall_summary"] == "helper startup blocked: helper_release_gate_failed"
    assert body["operator"]["severity"] == "error"
