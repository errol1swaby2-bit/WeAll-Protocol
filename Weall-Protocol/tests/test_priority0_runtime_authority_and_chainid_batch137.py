from __future__ import annotations

from fastapi import FastAPI
from fastapi.testclient import TestClient
import pytest

from weall.api.routes_public_parts.health import router as health_router
from weall.api.routes_public_parts.helper_readiness import router as helper_readiness_router
from weall.runtime.executor_boot import boot_config_from_env
from weall.runtime.helper_release_gate import build_helper_release_gate_report
from weall.runtime.helper_startup_integration import HelperStartupConfig, evaluate_helper_startup
from weall.runtime.mempool import PersistentMempool


def _all_green_report():
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


class _FakeExecutor:
    def snapshot(self):
        return {"chain_id": "weall-test", "node_id": "node-1", "height": 1, "tip": "tip-1"}

    def node_lifecycle_status(self):
        return {
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


def test_helper_startup_blocks_when_authority_not_effective_batch137() -> None:
    status = evaluate_helper_startup(
        config=HelperStartupConfig(helper_mode_requested=True, helper_authority_ok=False),
        helper_release_gate=_all_green_report(),
    )
    assert status.startup_allowed is False
    assert status.startup_mode == "blocked"
    assert status.code == "helper_authority_not_ready"


def test_helper_readiness_surfaces_authority_block_batch137(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("WEALL_MODE", "prod")
    monkeypatch.setenv("WEALL_HELPER_MODE_ENABLED", "1")
    app = FastAPI()
    app.include_router(helper_readiness_router)
    app.state.executor = _FakeExecutor()
    app.state.helper_release_gate_report = _all_green_report()
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
    assert body["helper_mode_requested"] is True
    assert body["helper_mode_effective"] is False
    assert body["startup"]["code"] == "helper_authority_not_ready"
    assert body["startup"]["startup_allowed"] is False


def test_health_helper_surface_surfaces_authority_block_batch137(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("WEALL_MODE", "prod")
    monkeypatch.setenv("WEALL_HELPER_MODE_ENABLED", "1")
    app = FastAPI()
    app.include_router(health_router)
    app.state.executor = _FakeExecutor()
    app.state.helper_release_gate_report = _all_green_report()
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
    body = TestClient(app).get("/health").json()["helper"]
    assert body["authority_contract"]["helper_requested"] is True
    assert body["helper_effective"] is False
    assert body["helper_status"] == "blocked"
    assert body["helper_startup"]["code"] == "helper_authority_not_ready"


def test_executor_boot_requires_explicit_chain_id_in_prod_batch137(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("WEALL_MODE", "prod")
    monkeypatch.delenv("WEALL_CHAIN_ID", raising=False)
    with pytest.raises(RuntimeError, match="Missing required env for production: WEALL_CHAIN_ID"):
        boot_config_from_env()


def test_persistent_mempool_requires_explicit_chain_id_in_prod_batch137(monkeypatch: pytest.MonkeyPatch, tmp_path) -> None:
    monkeypatch.setenv("WEALL_MODE", "prod")
    monkeypatch.setenv("WEALL_CHAIN_ID", "weall-test")
    with pytest.raises(ValueError, match="PersistentMempool requires an explicit chain_id in production"):
        PersistentMempool(db=__import__("weall.runtime.sqlite_db", fromlist=["SqliteDB"]).SqliteDB(path=str(tmp_path / "mempool.db")))
