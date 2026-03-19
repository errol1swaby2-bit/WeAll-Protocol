from __future__ import annotations

import json
from pathlib import Path

from weall.runtime.chain_config import load_chain_config
from weall.runtime.operator_incident_report import build_operator_incident_report
from weall.runtime.executor import WeAllExecutor


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


def test_operator_incident_report_is_ok_for_clean_local_state(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("WEALL_MODE", "testnet")
    monkeypatch.setenv("WEALL_NET_ENABLED", "0")
    monkeypatch.setenv("WEALL_BFT_ENABLED", "0")

    ex = _make_executor(tmp_path, chain_id="incident-clean")
    assert ex.submit_tx(
        {
            "tx_type": "ACCOUNT_REGISTER",
            "signer": "@alice",
            "nonce": 1,
            "payload": {"pubkey": "k:alice"},
        }
    )["ok"] is True
    assert ex.produce_block(max_txs=1).ok is True

    cfg = load_chain_config()
    cfg = cfg.__class__(**{**cfg.__dict__, "db_path": str(tmp_path / "node.db"), "tx_index_path": str(_repo_root() / "generated" / "tx_index.json"), "chain_id": "incident-clean", "node_id": "@validator"})

    report = build_operator_incident_report(
        cfg=cfg,
        db_path=Path(cfg.db_path),
        tx_index_path=Path(cfg.tx_index_path),
        remote_forensics=None,
    )

    assert report["ok"] is True
    assert report["summary"]["severity"] == "ok"
    assert report["snapshot"]["height"] == 1
    assert report["validator_set"]["epoch"] == 0
    assert isinstance(report["report_hash"], str)
    assert report["startup_fingerprint"]["chain_id"] == "incident-clean"


def test_operator_incident_report_escalates_remote_stall_to_critical(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("WEALL_MODE", "testnet")
    monkeypatch.setenv("WEALL_NET_ENABLED", "1")
    monkeypatch.setenv("WEALL_BFT_ENABLED", "1")

    ex = _make_executor(tmp_path, chain_id="incident-stall")
    cfg = load_chain_config()
    cfg = cfg.__class__(**{**cfg.__dict__, "db_path": str(tmp_path / "node.db"), "tx_index_path": str(_repo_root() / "generated" / "tx_index.json"), "chain_id": "incident-stall", "node_id": "@validator"})

    remote = {
        "ok": True,
        "stalled": True,
        "pending_fetch_requests_count": 2,
        "recent_rejection_summary": {"count": 3},
    }

    report = build_operator_incident_report(
        cfg=cfg,
        db_path=Path(cfg.db_path),
        tx_index_path=Path(cfg.tx_index_path),
        remote_forensics=remote,
    )

    assert report["ok"] is False
    assert report["summary"]["severity"] == "critical"
    assert report["summary"]["remote_stalled"] is True
    assert report["summary"]["pending_fetch_requests_count"] == 2
