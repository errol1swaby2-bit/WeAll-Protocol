from __future__ import annotations

import json
from pathlib import Path

from fastapi import FastAPI
from fastapi.testclient import TestClient

from weall.api.routes_public_parts.status import router as status_router
from weall.runtime.executor import WeAllExecutor


def _write_min_tx_index(path: Path) -> None:
    path.write_text(json.dumps({"by_name": {}, "by_id": {}, "tx_types": []}), encoding="utf-8")


def test_status_consensus_forensics_surfaces_profile_compatibility(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("WEALL_MODE", "prod")
    monkeypatch.setenv("WEALL_NODE_LIFECYCLE_STATE", "production_service")
    monkeypatch.setenv("WEALL_SERVICE_ROLES", "validator,helper")
    monkeypatch.setenv("WEALL_BFT_ENABLED", "1")
    monkeypatch.setenv("WEALL_HELPER_MODE_ENABLED", "1")
    monkeypatch.setenv("WEALL_PEER_PROFILE_ENFORCEMENT", "strict")
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

    app = FastAPI()
    app.include_router(status_router, prefix="/v1")
    app.state.executor = ex
    client = TestClient(app)

    resp = client.get("/v1/status/consensus/forensics")
    assert resp.status_code == 200
    body = resp.json()
    compat = body["profile_compatibility"]
    assert compat["requested_state"] == "production_service"
    assert compat["effective_state"] == "production_service"
    assert compat["authority_ready"] is True
    assert body["node_lifecycle"]["peer_profile_enforcement"] == "strict"
