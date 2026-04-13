from __future__ import annotations

import json
from pathlib import Path

import pytest

from weall.runtime.executor import ExecutorError, WeAllExecutor



def _write_min_tx_index(path: Path) -> None:
    path.write_text(json.dumps({"by_name": {}, "by_id": {}, "tx_types": []}), encoding="utf-8")



def test_invalid_lifecycle_state_refuses_startup(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("WEALL_MODE", "prod")
    monkeypatch.setenv("WEALL_NODE_LIFECYCLE_STATE", "production-ish")

    db_path = tmp_path / "weall.db"
    tx_index_path = tmp_path / "tx_index.json"
    _write_min_tx_index(tx_index_path)

    with pytest.raises(ExecutorError, match="node_lifecycle_startup_refused:CONFIG_INVALID_PROFILE"):
        WeAllExecutor(
            db_path=str(db_path),
            node_id="node-1",
            chain_id="weall-test",
            tx_index_path=str(tx_index_path),
        )



def test_invalid_service_role_refuses_startup(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("WEALL_MODE", "prod")
    monkeypatch.setenv("WEALL_NODE_LIFECYCLE_STATE", "production_service")
    monkeypatch.setenv("WEALL_SERVICE_ROLES", "validator,warpdrive")
    monkeypatch.setenv("WEALL_NODE_PUBKEY", "pub")
    monkeypatch.setenv("WEALL_VALIDATOR_ACCOUNT", "@v1")

    db_path = tmp_path / "weall.db"
    tx_index_path = tmp_path / "tx_index.json"
    _write_min_tx_index(tx_index_path)

    with pytest.raises(ExecutorError, match="CONFIG_INVALID_SERVICE_ROLE"):
        WeAllExecutor(
            db_path=str(db_path),
            node_id="@v1",
            chain_id="weall-test",
            tx_index_path=str(tx_index_path),
        )



def test_production_request_missing_account_enters_maintenance_restricted(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("WEALL_MODE", "prod")
    monkeypatch.setenv("WEALL_NODE_LIFECYCLE_STATE", "production_service")
    monkeypatch.setenv("WEALL_SERVICE_ROLES", "validator")
    monkeypatch.setenv("WEALL_BFT_ENABLED", "1")
    monkeypatch.setenv("WEALL_NODE_PUBKEY", "pub")
    monkeypatch.setenv("WEALL_VALIDATOR_ACCOUNT", "@v1")

    db_path = tmp_path / "weall.db"
    tx_index_path = tmp_path / "tx_index.json"
    _write_min_tx_index(tx_index_path)

    ex = WeAllExecutor(
        db_path=str(db_path),
        node_id="@v1",
        chain_id="weall-test",
        tx_index_path=str(tx_index_path),
    )
    lifecycle = ex.node_lifecycle_status()
    assert lifecycle["effective_state"] == "maintenance_restricted"
    assert lifecycle["startup_action"] == "maintenance_restricted"
    assert lifecycle["startup_refusal_required"] is False
    assert "ACCOUNT_NOT_FOUND" in lifecycle["promotion_failure_reasons"]
