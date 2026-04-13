from __future__ import annotations

import json
from pathlib import Path

from weall.runtime.executor import WeAllExecutor


def _write_min_tx_index(path: Path) -> None:
    path.write_text(json.dumps({"by_name": {}, "by_id": {}, "tx_types": []}), encoding="utf-8")



def test_default_node_lifecycle_is_bootstrap_registration(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("WEALL_MODE", "prod")
    monkeypatch.delenv("WEALL_NODE_LIFECYCLE_STATE", raising=False)
    monkeypatch.delenv("WEALL_SERVICE_ROLES", raising=False)
    monkeypatch.delenv("WEALL_VALIDATOR_ACCOUNT", raising=False)

    db_path = tmp_path / "weall.db"
    tx_index_path = tmp_path / "tx_index.json"
    _write_min_tx_index(tx_index_path)

    ex = WeAllExecutor(
        db_path=str(db_path),
        node_id="node-1",
        chain_id="weall-test",
        tx_index_path=str(tx_index_path),
    )
    lifecycle = ex.node_lifecycle_status()
    assert lifecycle["requested_state"] == "bootstrap_registration"
    assert lifecycle["effective_state"] == "bootstrap_registration"
    assert lifecycle["promotion_preflight_passed"] is False
    assert lifecycle["service_roles_effective"] == []
    assert lifecycle["promotion_failure_reasons"] == []
    assert lifecycle["schema_version"]
    assert lifecycle["tx_index_hash"]
    assert lifecycle["runtime_profile_hash"]



def test_production_request_without_bound_account_fails_closed_to_maintenance(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("WEALL_MODE", "prod")
    monkeypatch.setenv("WEALL_NODE_LIFECYCLE_STATE", "production_service")
    monkeypatch.setenv("WEALL_SERVICE_ROLES", "validator,helper")
    monkeypatch.setenv("WEALL_BFT_ENABLED", "1")
    monkeypatch.setenv("WEALL_HELPER_MODE_ENABLED", "1")
    monkeypatch.setenv("WEALL_NODE_PUBKEY", "pub")
    monkeypatch.delenv("WEALL_VALIDATOR_ACCOUNT", raising=False)
    monkeypatch.delenv("WEALL_BOUND_ACCOUNT", raising=False)

    db_path = tmp_path / "weall.db"
    tx_index_path = tmp_path / "tx_index.json"
    _write_min_tx_index(tx_index_path)

    ex = WeAllExecutor(
        db_path=str(db_path),
        node_id="node-1",
        chain_id="weall-test",
        tx_index_path=str(tx_index_path),
    )
    lifecycle = ex.node_lifecycle_status()
    assert lifecycle["requested_state"] == "production_service"
    assert lifecycle["effective_state"] == "maintenance_restricted"
    assert lifecycle["promotion_preflight_passed"] is False
    assert "ACCOUNT_NOT_BOUND" in lifecycle["promotion_failure_reasons"]
    assert lifecycle["service_roles_effective"] == []



def test_production_request_activates_validator_and_helper_when_preflight_passes(
    tmp_path: Path, monkeypatch
) -> None:
    monkeypatch.setenv("WEALL_MODE", "prod")
    monkeypatch.setenv("WEALL_NODE_LIFECYCLE_STATE", "production_service")
    monkeypatch.setenv("WEALL_SERVICE_ROLES", "validator,helper")
    monkeypatch.setenv("WEALL_BFT_ENABLED", "1")
    monkeypatch.setenv("WEALL_HELPER_MODE_ENABLED", "1")
    monkeypatch.setenv("WEALL_NODE_PUBKEY", "pub")
    monkeypatch.setenv("WEALL_VALIDATOR_ACCOUNT", "@v1")
    monkeypatch.setenv("WEALL_PRODUCTION_REQUIRED_REPUTATION_MILLI", "0")

    db_path = tmp_path / "weall.db"
    tx_index_path = tmp_path / "tx_index.json"
    _write_min_tx_index(tx_index_path)

    ex = WeAllExecutor(
        db_path=str(db_path),
        node_id="@v1",
        chain_id="weall-test",
        tx_index_path=str(tx_index_path),
    )
    st = ex.read_state()
    st["accounts"] = {
        "@v1": {
            "nonce": 0,
            "poh_tier": 3,
            "banned": False,
            "locked": False,
            "reputation_milli": 6000,
            "keys": {"by_id": {"main": {"pubkey": "pub", "revoked": False}}},
        }
    }
    st["roles"] = {
        "validators": {"active_set": ["@v1", "@v2", "@v3", "@v4"]},
        "node_operators": {"by_id": {"@v1": {"enrolled": True, "active": True}}, "active_set": ["@v1"]},
    }
    ex.state = st
    ex._persist_node_lifecycle_meta()  # type: ignore[attr-defined]
    ex._store.write_state_snapshot(ex.state)  # type: ignore[attr-defined]

    lifecycle = ex.node_lifecycle_status()
    assert lifecycle["requested_state"] == "production_service"
    assert lifecycle["effective_state"] == "production_service"
    assert lifecycle["promotion_preflight_passed"] is True
    assert lifecycle["helper_enabled_effective"] is True
    assert lifecycle["bft_enabled_effective"] is True
    assert lifecycle["node_key_authorized"] is True
    assert lifecycle["poh_tier_required"] == 3
    assert lifecycle["poh_tier_actual"] == 3
    assert lifecycle["reputation_actual_milli"] == 6000
    assert lifecycle["active_roles"] == ["helper", "node_operator", "storage_operator", "validator"]
    assert lifecycle["service_roles_effective"] == ["general_service", "helper", "validator"]
