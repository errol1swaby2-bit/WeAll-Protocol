from __future__ import annotations

import json
import sqlite3
import subprocess
import sys
from pathlib import Path

from weall.runtime.chain_config import ChainConfig, production_bootstrap_report


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


def _write_db(db_path: Path) -> None:
    state = {
        "meta": {
            "chain_id": "weall-prod",
            "schema_version": "1",
            "production_consensus_profile_hash": "",
            "tx_index_hash": "",
            "node_lifecycle": {
                "requested_state": "production_service",
                "effective_state": "production_service",
                "helper_enabled_requested": False,
                "helper_enabled_effective": False,
                "bft_enabled_requested": True,
                "bft_enabled_effective": True,
                "service_roles_requested": ["validator"],
                "service_roles_effective": ["validator"],
                "startup_action": "allow",
                "promotion_failure_reasons": [],
            },
        },
        "chain": {"height": 0, "block_id": "", "block_hash": "", "state_root": ""},
        "bft": {"finalized_height": 0, "finalized_block_id": ""},
        "consensus": {"epochs": {"current": 0}, "validator_set": {"set_hash": "", "active_set": []}},
        "roles": {"validators": {"active_set": []}},
    }
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


def test_production_bootstrap_report_surfaces_authority_contract_batch132(tmp_path: Path) -> None:
    cfg = _cfg(tmp_path)
    _write_db(Path(cfg.db_path))
    report = production_bootstrap_report(cfg)
    assert report["authority_contract_source"] == "runtime"
    assert report["authority_contract"]["requested_state"] == "production_service"
    assert report["authority_contract"]["validator_effective"] is True
    assert report["authority_contract"]["bft_effective"] is True


def test_build_validator_bootstrap_bundle_json_surfaces_authority_contract_batch132(tmp_path: Path) -> None:
    root = Path(__file__).resolve().parents[1]
    cfg = _cfg(tmp_path)
    _write_db(Path(cfg.db_path))
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
    out_path = tmp_path / "bundle.json"
    proc = subprocess.run(
        [sys.executable, "scripts/build_validator_bootstrap_bundle.py", "--out", str(out_path), "--json"],
        cwd=root,
        env={**dict(__import__("os").environ), "WEALL_CHAIN_CONFIG_PATH": str(cfg_path)},
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
    payload = json.loads(proc.stdout)
    assert payload["ok"] is True
    assert payload["bundle_path"] == str(out_path)
    assert payload["authority_contract"]["validator_effective"] is True
    assert payload["authority_contract_hash"]
