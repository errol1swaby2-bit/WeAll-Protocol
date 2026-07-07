from __future__ import annotations

import json
from pathlib import Path

from fastapi.testclient import TestClient

from weall.api.app import create_app
from weall.runtime.executor import WeAllExecutor


def _write_min_tx_index(path: Path) -> None:
    path.write_text(json.dumps({"by_name": {}, "by_id": {}, "tx_types": []}), encoding="utf-8")


def test_startup_posture_surfaces_runtime_open_and_recovery_mode(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("WEALL_MODE", "prod")
    monkeypatch.delenv("WEALL_OBSERVER_MODE", raising=False)
    monkeypatch.delenv("WEALL_ALLOW_DIRTY_SIGNING", raising=False)
    monkeypatch.delenv("WEALL_VALIDATOR_SIGNING_ENABLED", raising=False)
    monkeypatch.setenv("WEALL_VALIDATOR_ACCOUNT", "@v1")

    db_path = tmp_path / "weall.db"
    tx_index_path = tmp_path / "tx_index.json"
    _write_min_tx_index(tx_index_path)

    ex1 = WeAllExecutor(
        db_path=str(db_path),
        node_id="@v1",
        chain_id="weall-test",
        tx_index_path=str(tx_index_path),
    )
    app1 = create_app(boot_runtime=False)
    app1.state.executor = ex1
    client1 = TestClient(app1)
    startup1 = client1.get("/v1/status/operator").json()["operator"]["startup_posture"]
    assert startup1["last_shutdown_clean"] is True
    assert startup1["runtime_open"] is True
    assert startup1["recovery_mode_active"] is False

    ex2 = WeAllExecutor(
        db_path=str(db_path),
        node_id="@v1",
        chain_id="weall-test",
        tx_index_path=str(tx_index_path),
    )
    app2 = create_app(boot_runtime=False)
    app2.state.executor = ex2
    client2 = TestClient(app2)
    startup2 = client2.get("/v1/status/operator").json()["operator"]["startup_posture"]
    assert startup2["last_shutdown_clean"] is False
    assert startup2["runtime_open"] is True
    assert startup2["observer_mode"] is True
    assert startup2["signing_block_reason"] == "unclean_shutdown"
    assert startup2["recovery_mode_active"] is True

    ex2.mark_clean_shutdown()
    app2b = create_app(boot_runtime=False)
    app2b.state.executor = ex2
    client2b = TestClient(app2b)
    startup2b = client2b.get("/v1/status/operator").json()["operator"]["startup_posture"]
    assert startup2b["last_shutdown_clean"] is True
    assert startup2b["runtime_open"] is False
    assert startup2b["recovery_mode_active"] is False

    ex3 = WeAllExecutor(
        db_path=str(db_path),
        node_id="@v1",
        chain_id="weall-test",
        tx_index_path=str(tx_index_path),
    )
    app3 = create_app(boot_runtime=False)
    app3.state.executor = ex3
    client3 = TestClient(app3)
    startup3 = client3.get("/v1/status/operator").json()["operator"]["startup_posture"]
    assert startup3["last_shutdown_clean"] is True
    assert startup3["runtime_open"] is True
    assert startup3["observer_mode"] is False
    assert startup3["recovery_mode_active"] is False
