from __future__ import annotations

import json
import os
import sqlite3
import subprocess
import sys
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat

from weall.runtime.chain_config import (
    ChainConfig,
    production_bootstrap_issues,
    production_bootstrap_report,
)
from weall.testing.sigtools import deterministic_ed25519_keypair


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
    monkeypatch.setenv("WEALL_REQUIRE_SIGNED_BOOTSTRAP_MANIFEST", "1")


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


def _make_state() -> dict[str, object]:
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


def test_production_bootstrap_requires_signed_release_manifest(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _set_prod_env(monkeypatch)
    _write_db(Path(_cfg(tmp_path).db_path), _make_state())
    issues = production_bootstrap_issues(_cfg(tmp_path))
    assert any("missing signed release manifest" in issue for issue in issues)
    assert any("missing release manifest signer pubkey" in issue for issue in issues)


def test_signed_manifest_round_trip_and_report(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _set_prod_env(monkeypatch)
    cfg = _cfg(tmp_path)
    cfg_path = tmp_path / "prod.chain.json"
    cfg_path.write_text(json.dumps(cfg.__dict__), encoding="utf-8")
    _write_db(Path(cfg.db_path), _make_state())
    bundle_path = tmp_path / "release_manifest.json"

    pubkey, sk = deterministic_ed25519_keypair(label="release-signer")
    priv_hex = sk.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption()).hex()
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
        "WEALL_SYNC_REQUIRE_TRUSTED_ANCHOR": "1",
        "WEALL_NET_REQUIRE_PEER_IDENTITY": "1",
        "WEALL_NET_REQUIRE_IDENTITY": "1",
        "WEALL_NET_REQUIRE_IDENTITY_FOR_BFT": "1",
        "WEALL_SYNC_REQUIRE_HEADER_MATCH": "1",
        "WEALL_SYNC_ENFORCE_FINALIZED_ANCHOR": "1",
        "WEALL_BFT_FETCH_ENABLED": "1",
        "WEALL_BFT_FETCH_BASE_URLS": "https://peer-a.example,https://peer-b.example",
        "WEALL_PEER_ID": "validator-node-1",
        "WEALL_RELEASE_SIGNING_PRIVKEY": priv_hex,
        "WEALL_RELEASE_PUBKEY": pubkey,
        "WEALL_RELEASE_MANIFEST_PATH": str(bundle_path),
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
        [
            sys.executable,
            "scripts/verify_validator_bootstrap.py",
            "--bundle",
            str(bundle_path),
            "--release-pubkey",
            pubkey,
            "--json",
        ],
        cwd=Path(__file__).resolve().parents[1],
        env=cmd_env,
        check=False,
        capture_output=True,
        text=True,
    )
    assert verify.returncode == 0, verify.stdout + verify.stderr
    payload = json.loads(verify.stdout)
    assert payload["ok"] is True
    assert payload["release_manifest"]["ok"] is True
    monkeypatch.setenv("WEALL_RELEASE_PUBKEY", pubkey)
    monkeypatch.setenv("WEALL_RELEASE_MANIFEST_PATH", str(bundle_path))
    report = production_bootstrap_report(cfg)
    assert report["ok"] is True
    assert report["signed_release_manifest_required"] is True
    assert report["release_manifest"]["ok"] is True


def test_signed_manifest_detects_tamper(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _set_prod_env(monkeypatch)
    cfg = _cfg(tmp_path)
    _write_db(Path(cfg.db_path), _make_state())
    pubkey, sk = deterministic_ed25519_keypair(label="release-signer")
    priv_hex = sk.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption()).hex()
    monkeypatch.setenv("WEALL_RELEASE_SIGNING_PRIVKEY", priv_hex)
    monkeypatch.setenv("WEALL_RELEASE_PUBKEY", pubkey)
    from weall.runtime.bootstrap_manifest import build_manifest, sign_manifest

    manifest = sign_manifest(
        build_manifest(cfg, db_path=Path(cfg.db_path), tx_index_path=Path(cfg.tx_index_path)),
        privkey=priv_hex,
        signer_pubkey=pubkey,
    )
    manifest["chain_id"] = "evil-chain"
    bundle_path = tmp_path / "tampered_manifest.json"
    bundle_path.write_text(json.dumps(manifest), encoding="utf-8")
    monkeypatch.setenv("WEALL_RELEASE_MANIFEST_PATH", str(bundle_path))
    issues = production_bootstrap_issues(cfg)
    assert any(
        "manifest signature verification failed" in issue or "manifest chain_id mismatch" in issue
        for issue in issues
    )
