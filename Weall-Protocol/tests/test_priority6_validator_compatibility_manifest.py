from __future__ import annotations

import json
import sqlite3
from pathlib import Path

import pytest

from weall.runtime.bootstrap_manifest import build_manifest, verify_local_manifest
from weall.runtime.chain_config import (
    ChainConfig,
    chain_config_compatibility_hash,
    chain_config_compatibility_payload,
)


def _cfg(tmp_path: Path, *, block_interval_ms: int = 600_000, max_txs_per_block: int = 1000) -> ChainConfig:
    tx_index = tmp_path / "tx_index.json"
    tx_index.write_text("{}", encoding="utf-8")
    return ChainConfig(
        chain_id="weall-prod",
        node_id="node-1",
        mode="prod",
        db_path=str(tmp_path / "data" / "weall.db"),
        tx_index_path=str(tx_index),
        block_interval_ms=block_interval_ms,
        max_txs_per_block=max_txs_per_block,
        block_reward=0,
        api_host="127.0.0.1",
        api_port=8000,
        allow_unsigned_txs=False,
        log_level="INFO",
    )


def _write_db(db_path: Path, state: dict[str, object]) -> None:
    db_path.parent.mkdir(parents=True, exist_ok=True)
    con = sqlite3.connect(str(db_path))
    try:
        con.execute("CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT NOT NULL)")
        con.execute("CREATE TABLE ledger_state (id INTEGER PRIMARY KEY, state_json TEXT NOT NULL)")
        con.execute("INSERT INTO meta(key, value) VALUES (?, ?)", ("schema_version", "1"))
        con.execute("INSERT INTO ledger_state(id, state_json) VALUES (1, ?)", (json.dumps(_state()),))
        con.commit()
    finally:
        con.close()


def _state() -> dict[str, object]:
    return {
        "meta": {
            "chain_id": "weall-prod",
            "schema_version": "1",
            "production_consensus_profile_hash": "",
            "tx_index_hash": "",
        },
        "chain": {"height": 0, "block_id": "", "block_hash": "", "state_root": ""},
        "bft": {"finalized_height": 0, "finalized_block_id": ""},
        "consensus": {"epochs": {"current": 0}, "validator_set": {"set_hash": "", "active_set": []}},
        "roles": {"validators": {"active_set": []}},
    }


def test_build_manifest_commits_chain_config_compatibility(tmp_path: Path) -> None:
    cfg = _cfg(tmp_path)
    _write_db(Path(cfg.db_path), _state())
    manifest = build_manifest(cfg, db_path=Path(cfg.db_path), tx_index_path=Path(cfg.tx_index_path))
    assert manifest["chain_config_compatibility"] == chain_config_compatibility_payload(cfg)
    assert manifest["chain_config_compatibility_hash"] == chain_config_compatibility_hash(cfg)


def test_verify_local_manifest_rejects_chain_config_drift(tmp_path: Path) -> None:
    build_cfg = _cfg(tmp_path, block_interval_ms=600_000, max_txs_per_block=1000)
    verify_cfg = _cfg(tmp_path, block_interval_ms=300_000, max_txs_per_block=1000)
    _write_db(Path(build_cfg.db_path), _state())
    manifest = build_manifest(build_cfg, db_path=Path(build_cfg.db_path), tx_index_path=Path(build_cfg.tx_index_path))
    manifest_path = tmp_path / "bundle.json"
    manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True), encoding="utf-8")

    report = verify_local_manifest(cfg=verify_cfg, manifest_path=manifest_path, expected_pubkey="")
    assert report["ok"] is False
    assert any("chain_config_compatibility" in issue for issue in report["issues"])


def test_verify_local_manifest_rejects_manifest_payload_hash_mismatch(tmp_path: Path) -> None:
    cfg = _cfg(tmp_path)
    _write_db(Path(cfg.db_path), _state())
    manifest = build_manifest(cfg, db_path=Path(cfg.db_path), tx_index_path=Path(cfg.tx_index_path))
    manifest["chain_config_compatibility"]["block_interval_ms"] = 123456
    manifest_path = tmp_path / "bundle.json"
    manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True), encoding="utf-8")

    report = verify_local_manifest(cfg=cfg, manifest_path=manifest_path, expected_pubkey="")
    assert report["ok"] is False
    assert any("manifest_hash mismatch" in issue for issue in report["issues"])
