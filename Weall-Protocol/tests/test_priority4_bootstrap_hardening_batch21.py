from __future__ import annotations

import json
import os
import sqlite3
import subprocess
import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from weall.api.app import create_app
from weall.runtime.chain_config import ChainConfig, production_bootstrap_report, production_bootstrap_issues


class _FakePool:
    def size(self) -> int:
        return 0


class _FakeExecutor:
    def __init__(self) -> None:
        self.node_id = "node-1"
        self.mempool = _FakePool()
        self.attestation_pool = _FakePool()
        self.block_loop_running = True
        self.block_loop_unhealthy = False
        self.block_loop_last_error = ""
        self.block_loop_consecutive_failures = 0
        self._schema_version_cached = "1"
        self._bft_enabled = True

    def snapshot(self) -> dict[str, object]:
        return {
            "chain_id": "weall-prod",
            "height": 0,
            "tip": "",
            "meta": {"schema_version": "1", "tx_index_hash": "abc"},
            "roles": {"validators": {"active_set": ["@a", "@b", "@c"]}},
        }

    def read_state(self) -> dict[str, object]:
        return self.snapshot()

    def tx_index_hash(self) -> str:
        return "abc"

    def _current_validator_epoch(self) -> int:
        return 0

    def _current_validator_set_hash(self) -> str:
        return ""


class _FakeNetNode:
    def peers_debug(self) -> dict[str, object]:
        return {"counts": {}, "peers": []}


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


def _set_prod_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("WEALL_MODE", "prod")
    monkeypatch.setenv("WEALL_NET_ENABLED", "1")
    monkeypatch.setenv("WEALL_BFT_ENABLED", "1")
    monkeypatch.setenv("WEALL_NODE_PUBKEY", "pub")
    monkeypatch.setenv("WEALL_NODE_PRIVKEY", "priv")
    monkeypatch.setenv("WEALL_VALIDATOR_ACCOUNT", "@validator")
    monkeypatch.setenv("WEALL_STATE_SYNC_REQUIRE_TRUSTED_ANCHOR", "1")
    monkeypatch.setenv("WEALL_SYNC_REQUIRE_TRUSTED_ANCHOR", "1")
    monkeypatch.setenv("WEALL_NET_REQUIRE_PEER_IDENTITY", "1")
    monkeypatch.setenv("WEALL_NET_REQUIRE_IDENTITY", "1")
    monkeypatch.setenv("WEALL_NET_REQUIRE_IDENTITY_FOR_BFT", "1")
    monkeypatch.setenv("WEALL_SYNC_REQUIRE_HEADER_MATCH", "1")
    monkeypatch.setenv("WEALL_SYNC_ENFORCE_FINALIZED_ANCHOR", "1")
    monkeypatch.setenv("WEALL_BFT_FETCH_ENABLED", "1")
    monkeypatch.setenv("WEALL_BFT_FETCH_BASE_URLS", "https://peer-a.example,https://peer-b.example")
    monkeypatch.setenv("WEALL_PEER_ID", "validator-node-1")
    monkeypatch.setenv("GUNICORN_WORKERS", "1")
    monkeypatch.setenv("WEALL_BLOCK_LOOP_AUTOSTART", "0")
    monkeypatch.setenv("WEALL_NET_LOOP_AUTOSTART", "0")
    monkeypatch.delenv("WEALL_SIGVERIFY", raising=False)


def test_production_bootstrap_report_has_observer_first_guidance(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _set_prod_env(monkeypatch)
    report = production_bootstrap_report(_cfg(tmp_path))
    assert report["ok"] is True
    assert report["observer_first_recommended"] is True
    assert report["recommended_join_mode"] == "observer_first_then_verify_then_enable_bft_signing"
    assert report["fetch_sources_unique"] is True


def test_production_bootstrap_rejects_duplicate_fetch_sources(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _set_prod_env(monkeypatch)
    monkeypatch.setenv("WEALL_BFT_FETCH_BASE_URLS", "https://peer-a.example,https://peer-a.example/")
    issues = production_bootstrap_issues(_cfg(tmp_path))
    assert any("duplicate base URLs" in issue for issue in issues)


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


def test_bootstrap_bundle_builder_and_verifier_round_trip(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _set_prod_env(monkeypatch)
    cfg_path = tmp_path / "prod.chain.json"
    db_path = tmp_path / "data" / "weall.db"
    tx_index_path = tmp_path / "tx_index.json"
    tx_index_path.write_text("{}", encoding="utf-8")
    cfg_path.write_text(
        json.dumps(
            {
                "chain_id": "weall-prod",
                "node_id": "node-1",
                "mode": "prod",
                "db_path": str(db_path),
                "tx_index_path": str(tx_index_path),
                "block_interval_ms": 600000,
                "max_txs_per_block": 1000,
                "block_reward": 0,
                "api_host": "127.0.0.1",
                "api_port": 8000,
                "allow_unsigned_txs": False,
                "log_level": "INFO",
            }
        ),
        encoding="utf-8",
    )
    state = {
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
    _write_db(db_path, state)
    bundle_path = tmp_path / "bundle.json"

    cmd_env = {
        **dict(os.environ),
        "WEALL_CHAIN_CONFIG_PATH": str(cfg_path),
        "WEALL_MODE": "prod",
        "WEALL_NET_ENABLED": "1",
        "WEALL_BFT_ENABLED": "1",
        "WEALL_NODE_PUBKEY": "pub",
        "WEALL_NODE_PRIVKEY": "priv",
        "WEALL_VALIDATOR_ACCOUNT": "@validator",
        "WEALL_STATE_SYNC_REQUIRE_TRUSTED_ANCHOR": "1",
        "WEALL_NET_REQUIRE_PEER_IDENTITY": "1",
        "WEALL_NET_REQUIRE_IDENTITY": "1",
        "WEALL_NET_REQUIRE_IDENTITY_FOR_BFT": "1",
        "WEALL_SYNC_REQUIRE_HEADER_MATCH": "1",
        "WEALL_SYNC_ENFORCE_FINALIZED_ANCHOR": "1",
        "WEALL_BFT_FETCH_ENABLED": "1",
        "WEALL_BFT_FETCH_BASE_URLS": "https://peer-a.example,https://peer-b.example",
        "WEALL_PEER_ID": "validator-node-1",
    }
    build = subprocess.run(
        [sys.executable, "scripts/build_validator_bootstrap_bundle.py", "--out", str(bundle_path)],
        cwd=Path(__file__).resolve().parents[1],
        env=cmd_env,
        check=True,
        capture_output=True,
        text=True,
    )
    assert str(bundle_path) in build.stdout
    verify = subprocess.run(
        [sys.executable, "scripts/verify_validator_bootstrap.py", "--bundle", str(bundle_path), "--json"],
        cwd=Path(__file__).resolve().parents[1],
        env=cmd_env,
        check=False,
        capture_output=True,
        text=True,
    )
    assert verify.returncode == 0, verify.stdout + verify.stderr
    payload = json.loads(verify.stdout)
    assert payload["ok"] is True
    assert payload["bootstrap_report"]["ok"] is True
    assert payload["startup_fingerprint"]["expected"]["fingerprint"] == payload["startup_fingerprint"]["bundle"]["fingerprint"]


def test_status_operator_exposes_bootstrap_report(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    _set_prod_env(monkeypatch)
    tx_index = tmp_path / "tx_index.json"
    tx_index.write_text("{}", encoding="utf-8")
    cfg_path = tmp_path / "prod.chain.json"
    cfg_path.write_text(
        json.dumps(
            {
                "chain_id": "weall-prod",
                "node_id": "node-1",
                "mode": "prod",
                "db_path": str(tmp_path / "data" / "weall.db"),
                "tx_index_path": str(tx_index),
                "block_interval_ms": 600000,
                "max_txs_per_block": 1000,
                "block_reward": 0,
                "api_host": "127.0.0.1",
                "api_port": 8000,
                "allow_unsigned_txs": False,
                "log_level": "INFO",
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setenv("WEALL_CHAIN_CONFIG_PATH", str(cfg_path))
    app = create_app(boot_runtime=False)
    app.state.executor = _FakeExecutor()
    app.state.net_node = _FakeNetNode()
    client = TestClient(app)
    body = client.get("/v1/status/operator").json()
    assert body["bootstrap"]["ok"] is True
    assert body["bootstrap"]["observer_first_recommended"] is True
    assert body["bootstrap"]["recommended_join_mode"] == "observer_first_then_verify_then_enable_bft_signing"
