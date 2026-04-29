from __future__ import annotations

import json
import os
import sqlite3
import subprocess
import sys
from pathlib import Path

import pytest

from weall.runtime.bootstrap_manifest import build_manifest, verify_manifest_integrity
from weall.runtime.chain_config import ChainConfig


def _cfg(tmp_path: Path) -> ChainConfig:
    tx_index = tmp_path / "tx_index.json"
    tx_index.write_text("{}", encoding="utf-8")
    return ChainConfig(
        chain_id="weall-prod",
        node_id="node-1",
        mode="prod",
        db_path=str(tmp_path / "data" / "weall.db"),
        tx_index_path=str(tx_index),
        block_interval_ms=600_000,
        max_txs_per_block=1000,
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
        con.execute("INSERT INTO ledger_state(id, state_json) VALUES (1, ?)", (json.dumps(state),))
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
        "consensus": {
            "epochs": {"current": 0},
            "validator_set": {"set_hash": "", "active_set": []},
        },
        "roles": {"validators": {"active_set": []}},
    }


def test_manifest_hash_detects_tampering(tmp_path: Path) -> None:
    cfg = _cfg(tmp_path)
    _write_db(Path(cfg.db_path), _state())
    manifest = build_manifest(cfg, db_path=Path(cfg.db_path), tx_index_path=Path(cfg.tx_index_path))
    assert verify_manifest_integrity(manifest) == []
    tampered = dict(manifest)
    tampered["chain_id"] = "evil-chain"
    issues = verify_manifest_integrity(tampered)
    assert any("manifest_hash mismatch" in issue for issue in issues)


def test_verify_script_reports_bundle_integrity_issues(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    cfg = _cfg(tmp_path)
    _write_db(Path(cfg.db_path), _state())
    bundle = build_manifest(cfg, db_path=Path(cfg.db_path), tx_index_path=Path(cfg.tx_index_path))
    bundle["chain_id"] = "evil-chain"
    bundle_path = tmp_path / "bundle.json"
    bundle_path.write_text(json.dumps(bundle, indent=2, sort_keys=True), encoding="utf-8")

    cfg_path = tmp_path / "prod.chain.json"
    cfg_path.write_text(
        json.dumps(
            {
                "chain_id": cfg.chain_id,
                "node_id": cfg.node_id,
                "mode": cfg.mode,
                "db_path": cfg.db_path,
                "tx_index_path": cfg.tx_index_path,
                "block_interval_ms": cfg.block_interval_ms,
                "max_txs_per_block": cfg.max_txs_per_block,
                "block_reward": cfg.block_reward,
                "api_host": cfg.api_host,
                "api_port": cfg.api_port,
                "allow_unsigned_txs": cfg.allow_unsigned_txs,
                "log_level": cfg.log_level,
            }
        ),
        encoding="utf-8",
    )

    env = dict(os.environ)
    env["WEALL_CHAIN_CONFIG_PATH"] = str(cfg_path)
    proc = subprocess.run(
        [
            sys.executable,
            "scripts/verify_validator_bootstrap.py",
            "--bundle",
            str(bundle_path),
            "--json",
        ],
        cwd=Path(__file__).resolve().parents[1],
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 1
    payload = json.loads(proc.stdout)
    assert any(
        "manifest_hash mismatch" in issue
        for issue in (payload.get("bundle_integrity_issues") or [])
    )
