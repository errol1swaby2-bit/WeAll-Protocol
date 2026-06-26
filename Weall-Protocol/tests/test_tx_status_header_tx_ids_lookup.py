from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from types import SimpleNamespace


ROOT = Path(__file__).resolve().parents[1]


def test_tx_status_block_lookup_uses_header_tx_ids() -> None:
    src = (ROOT / "src" / "weall" / "api" / "routes_public_parts" / "tx.py").read_text(encoding="utf-8")
    fn = src.split("def _tx_block_lookup", 1)[1].split("def _http_requires_sig_by_default", 1)[0]

    assert "Header tx_ids are consensus-visible committed tx IDs" in fn
    assert "header_tx_ids = header.get(\"tx_ids\")" in fn
    assert fn.index("header_tx_ids = header.get(\"tx_ids\")") < fn.index("Fallback path: compute deterministic tx_id from tx envelopes")


def test_tx_block_lookup_finds_receiptless_committed_header_tx_id(tmp_path, monkeypatch) -> None:
    from weall.api.routes_public_parts import tx as tx_routes

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
    block = {
        "block_id": "block:header-only",
        "height": 7,
        "header": {"tx_ids": ["tx:header-only"], "block_ts_ms": 12345},
        "receipts": [],
        "txs": [],
    }
    con.execute(
        "INSERT INTO blocks(height, block_id, block_json, created_ts_ms) VALUES(?,?,?,?);",
        (7, "block:header-only", json.dumps(block, sort_keys=True), 12345),
    )
    con.commit()
    con.close()

    class _Db:
        def connection(self):
            conn = sqlite3.connect(db_path)
            conn.row_factory = sqlite3.Row
            return conn

    monkeypatch.setattr(tx_routes, "_safe_mempool", lambda _request: SimpleNamespace(db=_Db()))
    monkeypatch.setattr(tx_routes, "_safe_executor", lambda _request: SimpleNamespace(chain_id="weall-controlled-devnet"))

    found = tx_routes._tx_block_lookup(SimpleNamespace(), "tx:header-only")
    assert found == {
        "tx_id": "tx:header-only",
        "height": 7,
        "block_id": "block:header-only",
        "tx_type": "",
        "signer": "",
        "included_ts_ms": 12345,
    }
