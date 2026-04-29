from __future__ import annotations

from weall.runtime.node_runtime_config import resolve_node_runtime_config_from_env


def test_runtime_config_defaults_to_strict_bootstrap(monkeypatch) -> None:
    monkeypatch.delenv("WEALL_NODE_LIFECYCLE_STATE", raising=False)
    monkeypatch.delenv("WEALL_SERVICE_ROLES", raising=False)
    monkeypatch.delenv("WEALL_HELPER_MODE_ENABLED", raising=False)
    monkeypatch.delenv("WEALL_BFT_ENABLED", raising=False)
    monkeypatch.delenv("WEALL_PEER_PROFILE_ENFORCEMENT", raising=False)

    cfg = resolve_node_runtime_config_from_env()
    assert cfg.requested_state == "bootstrap_registration"
    assert cfg.requested_roles == ()
    assert cfg.peer_profile_enforcement == "strict"
    assert cfg.config_source_summary()["env_applied"] is False


def test_runtime_config_tracks_applied_env_and_invalid_roles(monkeypatch) -> None:
    monkeypatch.setenv("WEALL_NODE_LIFECYCLE_STATE", "production_service")
    monkeypatch.setenv("WEALL_SERVICE_ROLES", "validator,helper,not_a_role")
    monkeypatch.setenv("WEALL_HELPER_MODE_ENABLED", "1")
    monkeypatch.setenv("WEALL_BFT_ENABLED", "1")
    monkeypatch.setenv("WEALL_PEER_PROFILE_ENFORCEMENT", "advisory")

    cfg = resolve_node_runtime_config_from_env()
    assert cfg.requested_state == "production_service"
    assert cfg.requested_roles == ("validator", "helper", "not_a_role")
    assert cfg.invalid_roles == ("not_a_role",)
    assert cfg.helper_enabled_requested is True
    assert cfg.bft_enabled_requested is True
    assert cfg.peer_profile_enforcement == "advisory"
    summary = cfg.config_source_summary()
    assert summary["env_applied"] is True
    assert "WEALL_NODE_LIFECYCLE_STATE" in summary["env_vars_applied"]
    assert "WEALL_PEER_PROFILE_ENFORCEMENT" in summary["env_vars_applied"]
