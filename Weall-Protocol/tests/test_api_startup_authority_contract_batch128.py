from __future__ import annotations

from types import SimpleNamespace

import pytest


class _FakeExecutor(SimpleNamespace):
    pass


def test_create_app_boot_runtime_persists_startup_authority_contract(monkeypatch: pytest.MonkeyPatch) -> None:
    from weall.api import app as api_app

    monkeypatch.setenv("WEALL_MODE", "prod")
    monkeypatch.setenv("WEALL_CHAIN_ID", "weall-test")
    monkeypatch.setenv("WEALL_BFT_ENABLED", "0")

    ex = _FakeExecutor(
        chain_id="weall-test",
        node_lifecycle_status=lambda: {
            "requested_state": "production_service",
            "effective_state": "maintenance_restricted",
            "service_roles_requested": ["validator"],
            "service_roles_effective": [],
            "helper_enabled_requested": False,
            "helper_enabled_effective": False,
            "bft_enabled_requested": False,
            "bft_enabled_effective": False,
            "startup_action": "maintenance_restricted",
            "promotion_failure_reasons": ["ROLE_NOT_ACTIVE"],
        },
    )
    monkeypatch.setattr(api_app, "build_executor", lambda: ex)

    app = api_app.create_app(boot_runtime=True)
    contract = getattr(app.state, "startup_authority_contract", {})
    assert contract["strict_runtime_authority_mode"] is True
    assert contract["requested_state"] == "production_service"
    assert contract["effective_state"] == "maintenance_restricted"
    assert contract["validator_requested"] is True
    assert contract["validator_effective"] is False
    assert contract["promotion_failure_reasons"] == ["ROLE_NOT_ACTIVE"]


def test_create_app_fails_closed_when_prod_bft_requested_but_not_effective(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from weall.api import app as api_app

    monkeypatch.setenv("WEALL_MODE", "prod")
    monkeypatch.setenv("WEALL_CHAIN_ID", "weall-test")
    monkeypatch.setenv("WEALL_BFT_ENABLED", "1")
    monkeypatch.setenv("WEALL_NODE_LIFECYCLE_STATE", "production_service")
    monkeypatch.setenv("WEALL_SERVICE_ROLES", "validator")
    monkeypatch.setenv("WEALL_NODE_PUBKEY", "pub")
    monkeypatch.setenv("WEALL_NODE_PRIVKEY", "priv")

    ex = _FakeExecutor(
        chain_id="weall-test",
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
            "promotion_failure_reasons": ["ROLE_NOT_ACTIVE"],
        },
    )
    monkeypatch.setattr(api_app, "build_executor", lambda: ex)

    with pytest.raises(Exception, match="api_runtime_authority_validator_not_effective"):
        api_app.create_app(boot_runtime=True)
