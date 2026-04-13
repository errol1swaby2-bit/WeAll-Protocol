from __future__ import annotations

import json
from pathlib import Path

from fastapi import FastAPI
from fastapi.testclient import TestClient
import pytest

from weall.api.routes_public_parts.status import router as status_router
from weall.runtime.bootstrap_manifest import build_manifest, verify_local_manifest
from weall.runtime.chain_config import ChainConfig
from weall.runtime.executor import WeAllExecutor


def _write_min_tx_index(path: Path) -> None:
    path.write_text(json.dumps({"by_name": {}, "by_id": {}, "tx_types": []}), encoding="utf-8")


def _make_executor(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, *, acct: str = "@genesis-node") -> WeAllExecutor:
    monkeypatch.setenv("WEALL_MODE", "prod")
    monkeypatch.setenv("WEALL_CHAIN_ID", "weall-test")
    monkeypatch.setenv("WEALL_GENESIS_BOOTSTRAP_ENABLE", "1")
    monkeypatch.setenv("WEALL_GENESIS_BOOTSTRAP_ACCOUNT", acct)
    monkeypatch.setenv("WEALL_GENESIS_BOOTSTRAP_PUBKEY", f"ed25519:{acct}")
    monkeypatch.setenv("WEALL_NODE_ID", acct)
    monkeypatch.setenv("WEALL_GENESIS_BOOTSTRAP_REPUTATION", "2.5")
    monkeypatch.setenv("WEALL_GENESIS_BOOTSTRAP_STORAGE_CAPACITY_BYTES", "4096")

    db_path = tmp_path / "weall.db"
    tx_index_path = tmp_path / "tx_index.json"
    _write_min_tx_index(tx_index_path)
    return WeAllExecutor(
        db_path=str(db_path),
        node_id=acct,
        chain_id="weall-test",
        tx_index_path=str(tx_index_path),
    )


def test_status_consensus_surfaces_pinned_genesis_bootstrap_profile_batch133(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    ex = _make_executor(tmp_path, monkeypatch)

    app = FastAPI()
    app.include_router(status_router, prefix="/v1")
    app.state.executor = ex
    client = TestClient(app)

    body = client.get("/v1/status/consensus").json()
    startup = body["startup_posture"]
    compat = body["profile_compatibility"]

    assert startup["genesis_bootstrap_enabled"] is True
    assert startup["genesis_bootstrap_mode"] == "explicit"
    assert startup["genesis_bootstrap_profile"]["account"] == "@genesis-node"
    assert startup["genesis_bootstrap_profile_hash"]
    assert compat["genesis_bootstrap_enabled"] is True
    assert compat["genesis_bootstrap_mode"] == "explicit"
    assert compat["genesis_bootstrap_profile_hash"] == startup["genesis_bootstrap_profile_hash"]


def test_manifest_commits_pinned_genesis_bootstrap_profile_batch133(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    ex = _make_executor(tmp_path, monkeypatch)
    cfg = ChainConfig(
        chain_id="weall-test",
        node_id="@genesis-node",
        mode="prod",
        db_path=str(tmp_path / "weall.db"),
        tx_index_path=str(tmp_path / "tx_index.json"),
        block_interval_ms=600_000,
        max_txs_per_block=1000,
        block_reward=0,
        api_host="127.0.0.1",
        api_port=8000,
        allow_unsigned_txs=False,
        log_level="INFO",
    )
    manifest = build_manifest(cfg, db_path=Path(cfg.db_path), tx_index_path=Path(cfg.tx_index_path))

    assert manifest["genesis_bootstrap_profile"]["account"] == "@genesis-node"
    assert manifest["genesis_bootstrap_profile_hash"] == ex.state["meta"]["genesis_bootstrap_profile_hash"]


def test_verify_local_manifest_rejects_genesis_bootstrap_profile_drift_batch133(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _make_executor(tmp_path, monkeypatch, acct="@genesis-a")
    cfg = ChainConfig(
        chain_id="weall-test",
        node_id="@genesis-a",
        mode="prod",
        db_path=str(tmp_path / "weall.db"),
        tx_index_path=str(tmp_path / "tx_index.json"),
        block_interval_ms=600_000,
        max_txs_per_block=1000,
        block_reward=0,
        api_host="127.0.0.1",
        api_port=8000,
        allow_unsigned_txs=False,
        log_level="INFO",
    )
    manifest = build_manifest(cfg, db_path=Path(cfg.db_path), tx_index_path=Path(cfg.tx_index_path))
    manifest_path = tmp_path / "bundle.json"
    manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True), encoding="utf-8")

    manifest["genesis_bootstrap_profile"]["account"] = "@genesis-b"
    manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True), encoding="utf-8")

    report = verify_local_manifest(cfg=cfg, manifest_path=manifest_path, expected_pubkey="")
    assert report["ok"] is False
    assert any("genesis_bootstrap_profile" in issue for issue in report["issues"])
