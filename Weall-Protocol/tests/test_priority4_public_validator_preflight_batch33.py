from __future__ import annotations

import json
import os
import sqlite3
import subprocess
import sys
from pathlib import Path


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


def test_public_validator_preflight_passes_with_bundle(tmp_path: Path) -> None:
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
        [
            sys.executable,
            "scripts/public_validator_preflight.py",
            "--bundle",
            str(bundle_path),
            "--json",
        ],
        cwd=root,
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
    payload = json.loads(proc.stdout)
    assert payload["ok"] is True
    assert payload["bundle_verified"] is True
    assert payload["observer_first_required"] is True
    assert payload["bootstrap"]["ok"] is True
    assert payload["bundle_verification"]["ok"] is True
    assert payload["recommended_sequence"][0] == "verify local prod posture"
    assert payload["compatibility_contract"]["ok"] is True
    assert payload["authority_contract_source"] == "runtime"
    assert payload["authority_contract"]["strict_runtime_authority_mode"] is True
    assert payload["authority_contract"]["bft_requested"] is True
    assert payload["signing_ready"] is True
    assert payload["bundle_verification"]["authority_contract"]["validator_effective"] is True
    assert payload["bundle_verification"]["authority_contract_source"] == "runtime"
    assert payload["bundle_verification"]["compatibility_contract"]["field_status"]["authority_contract_payload"]["ok"] is True


def test_public_validator_preflight_fails_without_required_bundle(tmp_path: Path) -> None:
    root = Path(__file__).resolve().parents[1]
    db_path = tmp_path / "data" / "weall.db"
    tx_index_path = tmp_path / "tx_index.json"
    cfg_path = tmp_path / "prod.chain.json"
    tx_index_path.write_text("{}", encoding="utf-8")
    cfg_path.write_text(json.dumps(_cfg_payload(db_path, tx_index_path)), encoding="utf-8")
    _write_db(db_path, _state())
    env = _prod_env(cfg_path)

    proc = subprocess.run(
        [sys.executable, "scripts/public_validator_preflight.py", "--require-bundle", "--json"],
        cwd=root,
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 1
    payload = json.loads(proc.stdout)
    assert payload["ok"] is False
    assert any("missing required bootstrap bundle" in issue for issue in payload["issues"])


def test_bootstrap_prod_node_uses_single_preflight() -> None:
    text = (Path(__file__).resolve().parents[1] / "scripts" / "bootstrap_prod_node.sh").read_text(
        encoding="utf-8"
    )
    assert "public_validator_preflight.py" in text
    assert "authority contract" in text.lower()
    assert 'verify_validator_bootstrap.py --bundle "$BUNDLE_OUT"' not in text


def test_public_validator_preflight_surfaces_compatibility_drift(tmp_path: Path) -> None:
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

    bundle = json.loads(bundle_path.read_text(encoding="utf-8"))
    bundle["chain_config_compatibility"]["block_interval_ms"] = 123456
    bundle["manifest_hash"] = "tampered"
    bundle_path.write_text(json.dumps(bundle), encoding="utf-8")

    proc = subprocess.run(
        [
            sys.executable,
            "scripts/public_validator_preflight.py",
            "--bundle",
            str(bundle_path),
            "--json",
        ],
        cwd=root,
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 1
    payload = json.loads(proc.stdout)
    assert payload["compatibility_contract"]["ok"] is False
    assert "chain_config_compatibility_payload" in payload["compatibility_contract"]["mismatches"]
    assert payload["authority_contract_source"] == "runtime"
    assert payload["signing_ready"] is False


def test_public_validator_preflight_surfaces_authority_contract_drift(tmp_path: Path) -> None:
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

    bundle = json.loads(bundle_path.read_text(encoding="utf-8"))
    bundle["authority_contract"]["validator_effective"] = False
    bundle["manifest_hash"] = "tampered"
    bundle_path.write_text(json.dumps(bundle), encoding="utf-8")

    proc = subprocess.run(
        [sys.executable, "scripts/public_validator_preflight.py", "--bundle", str(bundle_path), "--json"],
        cwd=root,
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 1
    payload = json.loads(proc.stdout)
    contract = payload["bundle_verification"]["compatibility_contract"]
    assert contract["field_status"]["authority_contract_payload"]["ok"] is False
    assert "authority_contract_payload" in contract["mismatches"]
    assert payload["signing_ready"] is False
