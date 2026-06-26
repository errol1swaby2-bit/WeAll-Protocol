from __future__ import annotations

import json
import os
import sqlite3
import subprocess
import sys
from pathlib import Path

from weall.net.handshake import HandshakeConfig, HandshakeState, build_hello, process_inbound_hello


def _cfg(**kwargs):
    base = dict(
        chain_id="weall-prod",
        schema_version="1",
        tx_index_hash="abc123",
        peer_id="node-a",
        protocol_version="2026.03",
        protocol_profile_hash="profile-1",
        bft_enabled=True,
        validator_epoch=7,
        validator_set_hash="sethash-7",
        genesis_bootstrap_profile_hash="gbp-1",
        genesis_bootstrap_enabled=True,
        genesis_bootstrap_mode="explicit",
        require_protocol_profile_match=True,
        require_validator_epoch_match_for_bft=True,
        require_genesis_bootstrap_profile_match=True,
    )
    base.update(kwargs)
    return HandshakeConfig(**base)


def test_handshake_rejects_genesis_bootstrap_profile_hash_mismatch_batch134() -> None:
    state = HandshakeState(config=_cfg())
    hello = build_hello(_cfg(peer_id="node-b", genesis_bootstrap_profile_hash="gbp-2"))
    ack = process_inbound_hello(state, hello)
    assert ack.ok is False
    assert ack.reason == "genesis_bootstrap_profile_hash_mismatch"


def test_handshake_rejects_genesis_bootstrap_enabled_mismatch_batch134() -> None:
    state = HandshakeState(config=_cfg())
    hello = build_hello(
        _cfg(
            peer_id="node-b",
            genesis_bootstrap_profile_hash="",
            genesis_bootstrap_enabled=False,
            genesis_bootstrap_mode="disabled",
        )
    )
    ack = process_inbound_hello(state, hello)
    assert ack.ok is False
    assert ack.reason == "genesis_bootstrap_enabled_mismatch"


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
            "genesis_bootstrap_profile": {
                "enabled": True,
                "mode": "explicit",
                "account": "@genesis-node",
                "pubkey": "ed25519:pub",
                "reputation_milli": 1000,
                "storage_capacity_bytes": 0,
            },
            "genesis_bootstrap_profile_hash": "gbp-local",
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
        "consensus": {
            "epochs": {"current": 0},
            "validator_set": {"set_hash": "", "active_set": []},
        },
        "roles": {"validators": {"active_set": []}},
    }


def _cfg_payload(db_path: Path, tx_index_path: Path) -> dict[str, object]:
    return {
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


def _prod_env(cfg_path: Path) -> dict[str, str]:
    return {
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
        "WEALL_STARTUP_CLOCK_SANITY_REQUIRED": "1",
        "GUNICORN_WORKERS": "1",
    }


def test_public_validator_preflight_surfaces_genesis_bootstrap_contract_batch134(tmp_path: Path) -> None:
    root = Path(__file__).resolve().parents[1]
    db_path = tmp_path / "data" / "weall.db"
    tx_index_path = tmp_path / "tx_index.json"
    cfg_path = tmp_path / "prod.chain.json"
    bundle_path = tmp_path / "bundle.json"
    tx_index_path.write_text("{}", encoding="utf-8")
    cfg_path.write_text(json.dumps(_cfg_payload(db_path, tx_index_path)), encoding="utf-8")
    _write_db(db_path, _state())
    env = _prod_env(cfg_path)

    build = subprocess.run(
        [sys.executable, "scripts/build_validator_bootstrap_bundle.py", "--out", str(bundle_path)],
        cwd=root,
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    assert build.returncode == 0, build.stdout + build.stderr

    proc = subprocess.run(
        [sys.executable, "scripts/public_validator_preflight.py", "--bundle", str(bundle_path), "--json"],
        cwd=root,
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
    payload = json.loads(proc.stdout)
    contract = payload["genesis_bootstrap_contract"]
    assert contract["ok"] is True
    assert contract["local_profile_hash"] == "gbp-local"
    assert contract["bundle_profile_hash"] == "gbp-local"
    assert contract["local_enabled"] is True
    assert contract["bundle_enabled"] is True
    assert contract["local_mode"] == "explicit"
    assert contract["bundle_mode"] == "explicit"
