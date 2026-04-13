from __future__ import annotations

import json
from pathlib import Path

from fastapi import FastAPI
from fastapi.testclient import TestClient

from weall.api.routes_public_parts.status import router as status_router
from weall.runtime.executor import WeAllExecutor


def _write_min_tx_index(path: Path) -> None:
    path.write_text(json.dumps({"by_name": {}, "by_id": {}, "tx_types": []}), encoding="utf-8")


def test_status_surfaces_authority_contract_in_strict_runtime_mode_batch127(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("WEALL_MODE", "prod")
    monkeypatch.setenv("WEALL_NODE_LIFECYCLE_STATE", "production_service")
    monkeypatch.setenv("WEALL_SERVICE_ROLES", "validator,helper")
    monkeypatch.setenv("WEALL_BFT_ENABLED", "1")
    monkeypatch.setenv("WEALL_HELPER_MODE_ENABLED", "1")
    monkeypatch.setenv("WEALL_NODE_PUBKEY", "pub")
    monkeypatch.setenv("WEALL_BOUND_ACCOUNT", "@node1")

    db_path = tmp_path / "weall.db"
    tx_index_path = tmp_path / "tx_index.json"
    _write_min_tx_index(tx_index_path)

    ex = WeAllExecutor(db_path=str(db_path), node_id="node-1", chain_id="weall-test", tx_index_path=str(tx_index_path))

    app = FastAPI()
    app.include_router(status_router, prefix="/v1")
    app.state.executor = ex
    client = TestClient(app)

    body = client.get("/v1/status/consensus").json()
    contract = body["startup_posture"]["authority_contract"]
    assert contract["strict_runtime_authority_mode"] is True
    assert contract["validator_requested"] is True
    assert contract["validator_effective"] is False
    assert contract["helper_requested"] is True
    assert contract["helper_effective"] is False

    nested = body["profile_compatibility"]
    assert nested["strict_runtime_authority_mode"] is True
    assert nested["validator_requested"] is True
    assert nested["validator_effective"] is False


def test_status_operator_surfaces_authority_contract_in_bootstrap_dev_batch127(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("WEALL_MODE", "dev")
    monkeypatch.delenv("WEALL_NODE_LIFECYCLE_STATE", raising=False)
    monkeypatch.setenv("WEALL_BFT_ENABLED", "1")
    monkeypatch.setenv("WEALL_HELPER_MODE_ENABLED", "1")

    db_path = tmp_path / "weall.db"
    tx_index_path = tmp_path / "tx_index.json"
    _write_min_tx_index(tx_index_path)

    ex = WeAllExecutor(db_path=str(db_path), node_id="node-1", chain_id="weall-test", tx_index_path=str(tx_index_path))

    app = FastAPI()
    app.include_router(status_router, prefix="/v1")
    app.state.executor = ex
    client = TestClient(app)

    body = client.get("/v1/status/operator").json()
    contract = body["operator"]["authority_contract"]
    assert contract["strict_runtime_authority_mode"] is False
    assert contract["bft_requested"] is True
    assert contract["helper_requested"] is True
