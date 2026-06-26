from __future__ import annotations

import hashlib
import json
from pathlib import Path

from fastapi import FastAPI
from fastapi.testclient import TestClient

from weall.api.routes_public_parts.status import router as status_router
from weall.runtime.chain_config import load_chain_config, production_bootstrap_issues
from weall.runtime.chain_manifest import chain_manifest_status, load_chain_manifest
from weall.runtime.executor import WeAllExecutor
from weall.runtime.executor_boot import boot_config_from_env


def _write_json(path: Path, obj: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _write_tx_index(path: Path) -> str:
    obj = {"by_id": {}, "by_name": {}, "tx_types": []}
    _write_json(path, obj)
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _manifest(path: Path, *, chain_id: str, tx_index_hash: str) -> Path:
    _write_json(
        path,
        {
            "version": 1,
            "chain_id": chain_id,
            "profile": "production_service",
            "mode": "prod",
            "schema_version": "1",
            "genesis_hash": "a" * 64,
            "genesis_state_root": "b" * 64,
            "tx_index_hash": tx_index_hash,
            "protocol_profile_hash": "e" * 64,
            "constitution_version": "draft-2",
            "constitution_hash": "f" * 64,
            "constitution_traceability_hash": "1" * 64,
            "constitution_document_path": "docs/constitution/WEALL_GENESIS_CONSTITUTION_DRAFT_2.md",

            "genesis_time_ms": 0,
            "constitutional_clock": {
                "enabled": True,
                "target_block_interval_ms": 20000,
                "empty_blocks_enabled": True,
                "procedure_time_source": "finalized_block_height",
                "block_time_derivation": "genesis_time_plus_height_times_interval",
                "no_fast_forward": True,
                "no_height_skip": True,
                "allowed_clock_skew_ms": 2000,
                "genesis_time_ms": 0,
            },
            "authority_snapshot_version": 1,
            "trusted_authority_pubkeys": ["c" * 64],
        },
    )
    return path


def test_chain_manifest_status_accepts_pinned_tx_index(tmp_path: Path) -> None:
    tx_index = tmp_path / "tx_index.json"
    tx_hash = _write_tx_index(tx_index)
    manifest_path = _manifest(tmp_path / "chain.json", chain_id="weall-prod", tx_index_hash=tx_hash)

    manifest = load_chain_manifest(str(manifest_path), required=True)
    status = chain_manifest_status(
        manifest=manifest,
        chain_id="weall-prod",
        mode="prod",
        tx_index_path=str(tx_index),
        strict=True,
    )

    assert status["ok"] is True
    assert status["tx_index_hash_matches"] is True
    assert status["chain_id"] == "weall-prod"


def test_chain_manifest_status_rejects_wrong_tx_index(tmp_path: Path) -> None:
    tx_index = tmp_path / "tx_index.json"
    _write_tx_index(tx_index)
    manifest_path = _manifest(tmp_path / "chain.json", chain_id="weall-prod", tx_index_hash="d" * 64)

    manifest = load_chain_manifest(str(manifest_path), required=True)
    status = chain_manifest_status(
        manifest=manifest,
        chain_id="weall-prod",
        mode="prod",
        tx_index_path=str(tx_index),
        strict=True,
    )

    assert status["ok"] is False
    assert "chain_manifest_tx_index_hash_mismatch" in status["issues"]


def test_boot_config_uses_required_manifest_chain_id(
    tmp_path: Path, monkeypatch
) -> None:
    tx_index = tmp_path / "tx_index.json"
    tx_hash = _write_tx_index(tx_index)
    manifest_path = _manifest(tmp_path / "chain.json", chain_id="weall-prod", tx_index_hash=tx_hash)

    monkeypatch.setenv("WEALL_MODE", "prod")
    monkeypatch.setenv("WEALL_REQUIRE_CHAIN_MANIFEST", "1")
    monkeypatch.setenv("WEALL_CHAIN_MANIFEST_PATH", str(manifest_path))
    monkeypatch.delenv("WEALL_CHAIN_ID", raising=False)
    monkeypatch.setenv("WEALL_TX_INDEX_PATH", str(tx_index))

    cfg = boot_config_from_env()

    assert cfg.chain_id == "weall-prod"
    assert cfg.tx_index_path == str(tx_index)


def test_load_chain_config_surfaces_manifest_metadata(
    tmp_path: Path, monkeypatch
) -> None:
    tx_index = tmp_path / "tx_index.json"
    tx_hash = _write_tx_index(tx_index)
    manifest_path = _manifest(tmp_path / "chain.json", chain_id="weall-prod", tx_index_hash=tx_hash)
    chain_config = tmp_path / "prod.chain.json"
    _write_json(
        chain_config,
        {
            "chain_id": "weall-prod",
            "node_id": "node-a",
            "mode": "prod",
            "db_path": str(tmp_path / "weall.db"),
            "tx_index_path": str(tx_index),
            "block_interval_ms": 600000,
            "max_txs_per_block": 1000,
            "block_reward": 0,
            "api_host": "127.0.0.1",
            "api_port": 8000,
            "allow_unsigned_txs": False,
            "log_level": "INFO",
        },
    )

    monkeypatch.setenv("WEALL_MODE", "prod")
    monkeypatch.setenv("WEALL_REQUIRE_CHAIN_MANIFEST", "1")
    monkeypatch.setenv("WEALL_CHAIN_MANIFEST_PATH", str(manifest_path))
    cfg = load_chain_config(str(chain_config))

    assert cfg.chain_manifest_path == str(manifest_path)
    assert cfg.expected_tx_index_hash == tx_hash
    assert not any(x.startswith("chain_manifest:") for x in production_bootstrap_issues(cfg))


def test_chain_identity_route_surfaces_manifest(tmp_path: Path, monkeypatch) -> None:
    tx_index = tmp_path / "tx_index.json"
    tx_hash = _write_tx_index(tx_index)
    manifest_path = _manifest(tmp_path / "chain.json", chain_id="weall-prod", tx_index_hash=tx_hash)
    monkeypatch.setenv("WEALL_MODE", "prod")
    monkeypatch.setenv("WEALL_CHAIN_MANIFEST_PATH", str(manifest_path))

    ex = WeAllExecutor(
        db_path=str(tmp_path / "weall.db"),
        node_id="node-a",
        chain_id="weall-prod",
        tx_index_path=str(tx_index),
    )
    app = FastAPI()
    app.include_router(status_router, prefix="/v1")
    app.state.executor = ex
    client = TestClient(app)

    body = client.get("/v1/chain/identity").json()
    manifest = client.get("/v1/chain/manifest").json()

    assert body["chain_manifest"]["enabled"] is True
    assert body["chain_manifest"]["tx_index_hash_matches"] is True
    assert manifest["chain_id"] == "weall-prod"
