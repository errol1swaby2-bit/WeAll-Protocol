from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

from weall.runtime.chain_config import load_chain_config
from weall.runtime.executor import WeAllExecutor
from weall.runtime.operator_incident_lane import build_operator_incident_lane


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def _make_executor(tmp_path: Path, chain_id: str) -> WeAllExecutor:
    tx_index_path = str(_repo_root() / "generated" / "tx_index.json")
    return WeAllExecutor(
        db_path=str(tmp_path / "node.db"),
        node_id="@validator",
        chain_id=chain_id,
        tx_index_path=tx_index_path,
    )


def _cfg_for(tmp_path: Path, chain_id: str):
    cfg = load_chain_config()
    return cfg.__class__(
        **{
            **cfg.__dict__,
            "db_path": str(tmp_path / "node.db"),
            "tx_index_path": str(_repo_root() / "generated" / "tx_index.json"),
            "chain_id": chain_id,
            "node_id": "@validator",
        }
    )


def test_operator_incident_lane_is_normal_for_clean_local_state(
    tmp_path: Path, monkeypatch
) -> None:
    monkeypatch.setenv("WEALL_MODE", "testnet")
    monkeypatch.setenv("WEALL_NET_ENABLED", "0")
    monkeypatch.setenv("WEALL_BFT_ENABLED", "0")

    ex = _make_executor(tmp_path, chain_id="incident-lane-clean")
    assert (
        ex.submit_tx(
            {
                "tx_type": "ACCOUNT_REGISTER",
                "signer": "@alice",
                "nonce": 1,
                "payload": {"pubkey": "k:alice"},
            }
        )["ok"]
        is True
    )
    assert ex.produce_block(max_txs=1).ok is True

    lane = build_operator_incident_lane(
        cfg=_cfg_for(tmp_path, chain_id="incident-lane-clean"),
        db_path=tmp_path / "node.db",
        tx_index_path=_repo_root() / "generated" / "tx_index.json",
        remote_forensics=None,
        peer_reports=[],
    )

    assert lane["ok"] is True
    assert lane["safe_mode"]["mode"] == "normal"
    assert lane["actions"]["actions"] == []
    assert lane["peer_summary"]["divergence_count"] == 0
    assert lane["next_steps"] == ["continue normal operation"]


def test_operator_incident_lane_halts_on_peer_divergence(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("WEALL_MODE", "testnet")
    monkeypatch.setenv("WEALL_NET_ENABLED", "1")
    monkeypatch.setenv("WEALL_BFT_ENABLED", "1")

    _make_executor(tmp_path, chain_id="incident-lane-divergence")
    cfg = _cfg_for(tmp_path, chain_id="incident-lane-divergence")

    peer_report = {
        "summary": {"severity": "ok"},
        "snapshot": {"height": 9, "tip_hash": "peer-tip"},
        "validator_set": {"validator_set_hash": "peer-set", "epoch": 4},
        "startup_fingerprint": {"chain_id": "incident-lane-divergence", "node_id": "@peer"},
        "bootstrap_report": {"issues": []},
        "remote_forensics": {"stalled": False},
    }

    lane = build_operator_incident_lane(
        cfg=cfg,
        db_path=tmp_path / "node.db",
        tx_index_path=_repo_root() / "generated" / "tx_index.json",
        remote_forensics={"ok": True},
        peer_reports=[peer_report],
    )

    assert lane["ok"] is False
    assert lane["report"]["summary"]["peer_consensus_divergence"] is True
    assert lane["peer_summary"]["divergence_count"] == 1
    assert lane["safe_mode"]["halt_block_production"] is True
    assert "HALT_BLOCK_PRODUCTION" in lane["actions"]["actions"]
    assert any(
        "divergent tip/validator-set/startup-fingerprint" in step for step in lane["next_steps"]
    )


def test_operator_incident_lane_cli_writes_bundle(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("WEALL_MODE", "testnet")
    monkeypatch.setenv("WEALL_NET_ENABLED", "0")
    monkeypatch.setenv("WEALL_BFT_ENABLED", "0")

    ex = _make_executor(tmp_path, chain_id="incident-lane-cli")
    assert (
        ex.submit_tx(
            {
                "tx_type": "ACCOUNT_REGISTER",
                "signer": "@alice",
                "nonce": 1,
                "payload": {"pubkey": "k:alice"},
            }
        )["ok"]
        is True
    )
    assert ex.produce_block(max_txs=1).ok is True

    out_path = tmp_path / "lane.json"
    script = _repo_root() / "scripts" / "run_operator_incident_lane.py"
    env = {
        **dict(__import__("os").environ),
        "WEALL_DB_PATH": str(tmp_path / "node.db"),
        "WEALL_TX_INDEX_PATH": str(_repo_root() / "generated" / "tx_index.json"),
        "WEALL_CHAIN_ID": "incident-lane-cli",
        "WEALL_NODE_ID": "@validator",
        "WEALL_MODE": "testnet",
        "WEALL_NET_ENABLED": "0",
        "WEALL_BFT_ENABLED": "0",
    }

    proc = subprocess.run(
        [sys.executable, str(script), "--out", str(out_path)],
        check=False,
        cwd=str(_repo_root()),
        capture_output=True,
        text=True,
        env=env,
    )

    assert proc.returncode == 0, proc.stderr
    payload = json.loads(out_path.read_text(encoding="utf-8"))
    assert payload["ok"] is True
    assert payload["safe_mode"]["mode"] == "normal"
    assert isinstance(payload["lane_hash"], str)
