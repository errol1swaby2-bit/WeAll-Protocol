from __future__ import annotations

import json
from pathlib import Path

from fastapi.testclient import TestClient

from weall.api.app import create_app
from weall.runtime.executor import WeAllExecutor


def _write_min_tx_index(path: Path) -> None:
    path.write_text(json.dumps({"by_name": {}, "by_id": {}, "tx_types": []}), encoding="utf-8")


def test_status_surfaces_persisted_startup_posture_after_unclean_restart(
    tmp_path: Path, monkeypatch
) -> None:
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
    assert ex1.validator_signing_enabled() is True
    assert ex1.observer_mode() is False

    ex2 = WeAllExecutor(
        db_path=str(db_path),
        node_id="@v1",
        chain_id="weall-test",
        tx_index_path=str(tx_index_path),
    )
    assert ex2.validator_signing_enabled() is False
    assert ex2.observer_mode() is True

    app = create_app(boot_runtime=False)
    app.state.executor = ex2
    client = TestClient(app)

    operator = client.get("/v1/status/operator")
    assert operator.status_code == 200
    operator_body = operator.json()
    startup = operator_body["operator"]["startup_posture"]
    lifecycle = operator_body["operator"]["node_lifecycle"]
    assert startup["last_shutdown_clean"] is False
    assert startup["validator_signing_enabled"] is False
    assert startup["observer_mode"] is True
    assert startup["signing_block_reason"] == "unclean_shutdown"
    assert startup["production_consensus_profile_hash"]
    assert lifecycle["requested_state"] == "bootstrap_registration"
    assert lifecycle["effective_state"] == "bootstrap_registration"

    consensus = client.get("/v1/status/consensus")
    assert consensus.status_code == 200
    consensus_body = consensus.json()
    assert consensus_body["startup_posture"]["observer_mode"] is True
    assert consensus_body["node_lifecycle"]["effective_state"] == "bootstrap_registration"
    assert consensus_body["startup_posture"]["signing_block_reason"] == "unclean_shutdown"

    forensics = client.get("/v1/status/consensus/forensics")
    assert forensics.status_code == 200
    forensics_body = forensics.json()
    assert forensics_body["startup_posture"]["last_shutdown_clean"] is False
    assert forensics_body["startup_posture"]["observer_mode"] is True

    ex2.mark_clean_shutdown()
    ex3 = WeAllExecutor(
        db_path=str(db_path),
        node_id="@v1",
        chain_id="weall-test",
        tx_index_path=str(tx_index_path),
    )
    assert ex3.validator_signing_enabled() is True
    assert ex3.observer_mode() is False

    app2 = create_app(boot_runtime=False)
    app2.state.executor = ex3
    client2 = TestClient(app2)
    healed = client2.get("/v1/status/operator")
    assert healed.status_code == 200
    healed_startup = healed.json()["operator"]["startup_posture"]
    assert healed_startup["last_shutdown_clean"] is True
    assert healed_startup["observer_mode"] is False
    assert healed_startup["signing_block_reason"] == ""
