from __future__ import annotations

from fastapi import FastAPI
from fastapi.testclient import TestClient

from weall.api.routes_public_parts.helper_readiness import router as helper_readiness_router
from weall.api.routes_public_parts.status import router as status_router
from weall.runtime.helper_release_gate import build_helper_release_gate_report


class _FakeExecutor:
    def snapshot(self):
        return {
            "chain_id": "weall",
            "node_id": "node-1",
            "height": 101,
            "tip": "tip-101",
        }

    def read_state(self):
        return {
            "chain_id": "weall",
            "height": 101,
            "tip": "tip-101",
            "tip_hash": "hash-101",
            "tip_ts_ms": 1700000000101,
            "accounts": {},
            "blocks": {},
            "params": {},
            "poh": {},
            "roles": {},
        }

    def tx_index_hash(self) -> str:
        return "txindexhash-101"


def _blocked_report():
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


def test_operator_status_and_helper_readiness_agree_when_blocked_batch45(monkeypatch) -> None:
    monkeypatch.setenv("WEALL_HELPER_MODE_ENABLED", "1")

    app = FastAPI()
    app.include_router(status_router)
    app.include_router(helper_readiness_router)
    app.state.executor = _FakeExecutor()
    app.state.helper_release_gate_report = _blocked_report()

    client = TestClient(app)

    operator = client.get("/status/operator")
    readiness = client.get("/status/helper/readiness")

    assert operator.status_code == 200
    assert readiness.status_code == 200

    op = operator.json()
    rd = readiness.json()

    assert op["operator"]["helper_status"] == "blocked"
    assert op["operator"]["helper_severity"] == "error"
    assert op["operator"]["helper_summary"] == "startup blocked: helper_release_gate_failed"

    assert rd["overall_status"] == "blocked"
    assert rd["overall_summary"] == "helper startup blocked: helper_release_gate_failed"
    assert rd["operator"]["severity"] == "error"
    assert rd["startup"]["startup_allowed"] is False
    assert rd["startup"]["helper_mode_active"] is False
    assert rd["chain_id"] == "weall"
