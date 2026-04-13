from __future__ import annotations

import json
from pathlib import Path

from weall.runtime.executor import WeAllExecutor


def _write_min_tx_index(path: Path) -> None:
    path.write_text(json.dumps({"by_name": {}, "by_id": {}, "tx_types": []}), encoding="utf-8")



def test_production_request_with_wrong_node_key_enters_maintenance(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("WEALL_MODE", "prod")
    monkeypatch.setenv("WEALL_NODE_LIFECYCLE_STATE", "production_service")
    monkeypatch.setenv("WEALL_SERVICE_ROLES", "validator")
    monkeypatch.setenv("WEALL_BFT_ENABLED", "1")
    monkeypatch.setenv("WEALL_NODE_PUBKEY", "wrong-pub")
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
            "reputation_milli": 7000,
            "keys": {"by_id": {"main": {"pubkey": "right-pub", "revoked": False}}},
        }
    }
    st["roles"] = {"validators": {"active_set": ["@v1", "@v2", "@v3", "@v4"]}}
    ex.state = st
    ex._persist_node_lifecycle_meta()  # type: ignore[attr-defined]
    ex._store.write_state_snapshot(ex.state)  # type: ignore[attr-defined]

    lifecycle = ex.node_lifecycle_status()
    assert lifecycle["effective_state"] == "maintenance_restricted"
    assert "NODE_KEY_NOT_AUTHORIZED" in lifecycle["promotion_failure_reasons"]
    assert lifecycle["node_key_authorized"] is False



def test_production_request_requires_requested_roles_to_be_active(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("WEALL_MODE", "prod")
    monkeypatch.setenv("WEALL_NODE_LIFECYCLE_STATE", "production_service")
    monkeypatch.setenv("WEALL_SERVICE_ROLES", "helper")
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
            "reputation_milli": 4000,
            "keys": {"by_id": {"main": {"pubkey": "pub", "revoked": False}}},
        }
    }
    st["roles"] = {
        "node_operators": {"by_id": {"@v1": {"enrolled": True, "active": False}}, "active_set": []}
    }
    ex.state = st
    ex._persist_node_lifecycle_meta()  # type: ignore[attr-defined]
    ex._store.write_state_snapshot(ex.state)  # type: ignore[attr-defined]

    lifecycle = ex.node_lifecycle_status()
    assert lifecycle["effective_state"] == "maintenance_restricted"
    assert "ROLE_NOT_ACTIVE" in lifecycle["promotion_failure_reasons"]
    assert lifecycle["active_roles"] == []
    assert lifecycle["suspended_roles"] == ["helper", "node_operator", "storage_operator"]
    assert lifecycle["service_roles_effective"] == []
