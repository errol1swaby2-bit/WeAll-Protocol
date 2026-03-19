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
        "chain_id": "weall-prod",
        "height": 0,
        "tip": "",
        "tip_hash": "",
        "finalized": {"height": 0, "block_id": ""},
        "meta": {
            "tx_index_hash": "",
            "schema_version": "1",
            "production_consensus_profile_hash": "",
        },
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


def test_public_validator_preflight_writes_incident_lane_bundle(tmp_path: Path) -> None:
    root = Path(__file__).resolve().parents[1]
    db_path = tmp_path / "data" / "weall.db"
    tx_index_path = tmp_path / "tx_index.json"
    cfg_path = tmp_path / "prod.chain.json"
    bundle_path = tmp_path / "bundle.json"
    lane_path = tmp_path / "incident_lane.json"
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
            "--incident-lane-out",
            str(lane_path),
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
    lane = json.loads(lane_path.read_text(encoding="utf-8"))
    assert payload["incident_lane"]["safe_mode"] == "normal"
    assert payload["recommended_sequence"][1] == "build and review operator incident lane"
    assert payload["compatibility_contract"]["ok"] is True
    assert lane["safe_mode"]["mode"] == "normal"
    assert isinstance(lane["lane_hash"], str)


def test_build_operator_incident_report_can_embed_lane_summary(tmp_path: Path) -> None:
    root = Path(__file__).resolve().parents[1]
    db_path = tmp_path / "data" / "weall.db"
    tx_index_path = tmp_path / "tx_index.json"
    cfg_path = tmp_path / "prod.chain.json"
    out_path = tmp_path / "report.json"
    lane_path = tmp_path / "lane.json"
    tx_index_path.write_text("{}", encoding="utf-8")
    cfg_path.write_text(json.dumps(_cfg_payload(db_path, tx_index_path)), encoding="utf-8")
    _write_db(db_path, _state())
    env = _prod_env(cfg_path)

    proc = subprocess.run(
        [
            sys.executable,
            "scripts/build_operator_incident_report.py",
            "--out",
            str(out_path),
            "--lane-out",
            str(lane_path),
            "--include-lane-summary",
        ],
        cwd=root,
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
    report = json.loads(out_path.read_text(encoding="utf-8"))
    lane = json.loads(lane_path.read_text(encoding="utf-8"))
    assert report["incident_lane"]["safe_mode"] == "normal"
    assert report["incident_lane"]["lane_hash"] == lane["lane_hash"]
    assert lane["safe_mode"]["mode"] == "normal"
    assert report["compatibility_contract"]["ok"] is True
    assert report["summary"]["compatibility_contract_ok"] is True


def test_bootstrap_prod_node_mentions_incident_lane() -> None:
    text = (Path(__file__).resolve().parents[1] / "scripts" / "bootstrap_prod_node.sh").read_text(
        encoding="utf-8"
    )
    assert (
        'public_validator_preflight.py --bundle "$BUNDLE_OUT" --incident-lane-out "$INCIDENT_LANE_OUT"'
        in text
    )
    assert "Operator incident lane" in text
    assert "build_operator_incident_report.py --include-lane-summary --lane-out" in text


def test_build_operator_incident_report_marks_compatibility_drift_critical(tmp_path: Path) -> None:
    root = Path(__file__).resolve().parents[1]
    db_path = tmp_path / "data" / "weall.db"
    tx_index_path = tmp_path / "tx_index.json"
    cfg_path = tmp_path / "prod.chain.json"
    bundle_path = tmp_path / "bundle.json"
    out_path = tmp_path / "report.json"
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
    bundle["chain_config_compatibility"]["allow_unsigned_txs"] = True
    bundle["manifest_hash"] = "tampered"
    bundle_path.write_text(json.dumps(bundle), encoding="utf-8")
    env["WEALL_RELEASE_MANIFEST_PATH"] = str(bundle_path)

    proc = subprocess.run(
        [
            sys.executable,
            "scripts/build_operator_incident_report.py",
            "--out",
            str(out_path),
            "--include-lane-summary",
        ],
        cwd=root,
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
    report = json.loads(out_path.read_text(encoding="utf-8"))
    assert report["summary"]["compatibility_contract_ok"] is False
    assert report["summary"]["severity"] == "critical"
    assert "chain_config_compatibility_payload" in report["compatibility_contract"]["mismatches"]
