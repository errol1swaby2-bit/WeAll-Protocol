from __future__ import annotations

import json
from pathlib import Path

from fastapi import FastAPI
from fastapi.testclient import TestClient

from weall.api.routes_public_parts.status import router as status_router
from weall.runtime.executor import WeAllExecutor
from weall.runtime.state_hash import compute_state_root


def _write_min_tx_index(path: Path) -> None:
    path.write_text(json.dumps({"by_name": {}, "by_id": {}, "tx_types": []}), encoding="utf-8")


def _client(tmp_path: Path) -> tuple[TestClient, WeAllExecutor]:
    tx_index = tmp_path / "tx_index.json"
    _write_min_tx_index(tx_index)
    ex = WeAllExecutor(
        db_path=str(tmp_path / "weall.db"),
        node_id="@node-a",
        chain_id="weall-devnet-test",
        tx_index_path=str(tx_index),
    )
    app = FastAPI()
    app.include_router(status_router, prefix="/v1")
    app.state.executor = ex
    return TestClient(app), ex


def test_chain_identity_route_surfaces_state_root_and_sync_anchor_batch208(tmp_path: Path) -> None:
    client, ex = _client(tmp_path)

    body = client.get("/v1/chain/identity").json()

    assert body["ok"] is True
    assert body["chain_id"] == "weall-devnet-test"
    assert body["height"] == 0
    assert body["state_root"] == compute_state_root(ex.snapshot())
    assert body["snapshot_anchor"]["state_root"] == body["state_root"]
    assert body["snapshot_anchor"]["height"] == body["height"]
    assert body["tx_index_hash"] == ex.tx_index_hash()
    assert isinstance(body["protocol_profile_hash"], str)
    assert isinstance(body["genesis_bootstrap"], dict)


def test_chain_state_root_and_genesis_routes_are_join_runbook_safe_batch208(tmp_path: Path) -> None:
    client, ex = _client(tmp_path)

    state_root = client.get("/v1/chain/state-root").json()
    genesis = client.get("/v1/chain/genesis").json()
    head = client.get("/v1/chain/head").json()

    assert state_root["ok"] is True
    assert state_root["state_root"] == compute_state_root(ex.snapshot())
    assert state_root["snapshot_anchor"]["state_root"] == state_root["state_root"]

    assert genesis["ok"] is True
    assert genesis["chain_id"] == "weall-devnet-test"
    assert genesis["tx_index_hash"] == ex.tx_index_hash()
    assert genesis["trusted_anchor"]["state_root"] == state_root["state_root"]
    assert "profile_hash" in genesis["genesis_bootstrap"]

    assert head["ok"] is True
    assert head["state_root"] == state_root["state_root"]
    assert head["tip_hash"] == state_root["tip_hash"]
