from __future__ import annotations

import json
import sqlite3
from types import SimpleNamespace


def _db(tmp_path, *, include_index: bool, apply_ok: bool = False):
    db_path = tmp_path / "weall.db"
    con = sqlite3.connect(db_path)
    con.execute(
        """
        CREATE TABLE blocks (
          height INTEGER PRIMARY KEY,
          block_id TEXT NOT NULL,
          block_json TEXT NOT NULL,
          created_ts_ms INTEGER NOT NULL
        );
        """
    )
    if include_index:
        con.execute(
            """
            CREATE TABLE tx_index (
              tx_id TEXT PRIMARY KEY,
              height INTEGER NOT NULL,
              block_id TEXT NOT NULL,
              tx_type TEXT NOT NULL,
              signer TEXT NOT NULL,
              nonce INTEGER NOT NULL,
              ok INTEGER NOT NULL,
              included_ts_ms INTEGER NOT NULL
            );
            """
        )
        con.execute(
            "INSERT INTO tx_index(tx_id,height,block_id,tx_type,signer,nonce,ok,included_ts_ms) VALUES(?,?,?,?,?,?,?,?);",
            ("tx:apply-rejected", 12, "block:12", "GOV_VOTE_CAST", "@member", 7, 1 if apply_ok else 0, 240000),
        )
    receipt = {
        "tx_id": "tx:apply-rejected",
        "tx_type": "GOV_VOTE_CAST",
        "signer": "@member",
        "nonce": 7,
        "ok": apply_ok,
    }
    if not apply_ok:
        receipt.update(
            {
                "code": "conflict",
                "reason": "ballot_already_final",
                "details": {"proposal_id": "proposal:negative", "signer": "@member"},
            }
        )
    block = {
        "block_id": "block:12",
        "height": 12,
        "header": {"tx_ids": ["tx:apply-rejected"], "block_ts_ms": 240000},
        "receipts": [receipt],
        "txs": [],
    }
    con.execute(
        "INSERT INTO blocks(height,block_id,block_json,created_ts_ms) VALUES(?,?,?,?);",
        (12, "block:12", json.dumps(block, sort_keys=True), 240000),
    )
    con.commit()
    con.close()

    class _Db:
        def connection(self):
            conn = sqlite3.connect(db_path)
            conn.row_factory = sqlite3.Row
            return conn

    return _Db()


def _wire(monkeypatch, db) -> None:
    from weall.api.routes_public_parts import tx as tx_routes

    monkeypatch.setattr(tx_routes, "_safe_mempool", lambda _request: SimpleNamespace(db=db, contains=lambda _tx_id: False))
    monkeypatch.setattr(tx_routes, "_safe_executor", lambda _request: SimpleNamespace(chain_id="weall-controlled-devnet"))
    monkeypatch.setattr(tx_routes, "_tx_queue_summary_for_tx", lambda _tx_id: None)


def test_tx_status_reports_indexed_apply_rejection_with_exact_receipt_truth(tmp_path, monkeypatch) -> None:
    from weall.api.routes_public_parts import tx as tx_routes

    _wire(monkeypatch, _db(tmp_path, include_index=True, apply_ok=False))
    status = tx_routes.tx_status(SimpleNamespace(), "tx:apply-rejected")

    assert status["ok"] is True
    assert status["status"] == "rejected"
    assert status["apply_ok"] is False
    assert status["source"] == "committed_apply_receipt"
    assert status["code"] == "conflict"
    assert status["reason"] == "ballot_already_final"
    assert status["details"] == {"proposal_id": "proposal:negative", "signer": "@member"}
    assert status["height"] == 12
    assert status["block_id"] == "block:12"
    assert status["local_state_synced"] is True


def test_tx_status_block_fallback_preserves_apply_rejection_truth_without_index(tmp_path, monkeypatch) -> None:
    from weall.api.routes_public_parts import tx as tx_routes

    _wire(monkeypatch, _db(tmp_path, include_index=False, apply_ok=False))
    status = tx_routes.tx_status(SimpleNamespace(), "tx:apply-rejected")

    assert status["status"] == "rejected"
    assert status["apply_ok"] is False
    assert status["code"] == "conflict"
    assert status["reason"] == "ballot_already_final"
    assert status["block_id"] == "block:12"



def test_tx_status_indexed_rejection_recovers_exact_receipt_beyond_recent_scan_window(tmp_path, monkeypatch) -> None:
    from weall.api.routes_public_parts import tx as tx_routes

    db = _db(tmp_path, include_index=True, apply_ok=False)
    with db.connection() as con:
        for height in range(13, 313):
            block_id = f"block:{height}"
            block = {
                "block_id": block_id,
                "height": height,
                "header": {"tx_ids": [], "block_ts_ms": height * 20_000},
                "receipts": [],
                "txs": [],
            }
            con.execute(
                "INSERT INTO blocks(height,block_id,block_json,created_ts_ms) VALUES(?,?,?,?);",
                (height, block_id, json.dumps(block, sort_keys=True), height * 20_000),
            )
        con.commit()

    _wire(monkeypatch, db)
    status = tx_routes.tx_status(SimpleNamespace(), "tx:apply-rejected")

    assert status["status"] == "rejected"
    assert status["apply_ok"] is False
    assert status["source"] == "committed_apply_receipt"
    assert status["code"] == "conflict"
    assert status["reason"] == "ballot_already_final"
    assert status["details"] == {"proposal_id": "proposal:negative", "signer": "@member"}
    assert status["height"] == 12
    assert status["block_id"] == "block:12"

def test_tx_status_successful_receipt_remains_confirmed(tmp_path, monkeypatch) -> None:
    from weall.api.routes_public_parts import tx as tx_routes

    _wire(monkeypatch, _db(tmp_path, include_index=True, apply_ok=True))
    status = tx_routes.tx_status(SimpleNamespace(), "tx:apply-rejected")

    assert status["status"] == "confirmed"
    assert status["apply_ok"] is True
    assert "code" not in status
    assert "reason" not in status
