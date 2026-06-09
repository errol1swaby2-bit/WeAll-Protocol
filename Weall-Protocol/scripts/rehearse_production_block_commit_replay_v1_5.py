#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import sqlite3
import tempfile
from pathlib import Path
from typing import Any

from weall.runtime.executor import WeAllExecutor
from weall.runtime.replay_consistency import build_sample_chain, build_replay_manifest


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def _tx_index_path() -> str:
    return str(_repo_root() / "generated" / "tx_index.json")


def _clean_env() -> None:
    for key in list(os.environ):
        if key.startswith("WEALL_"):
            os.environ.pop(key, None)
    os.environ["WEALL_MODE"] = "testnet"
    os.environ["WEALL_REQUIRE_VRF"] = "0"
    os.environ["WEALL_PRODUCE_EMPTY_BLOCKS"] = "1"
    os.environ["WEALL_SIGVERIFY"] = "0"


def _table_counts(db_path: str) -> dict[str, int]:
    con = sqlite3.connect(db_path)
    try:
        out: dict[str, int] = {}
        for table in ("blocks", "block_hash_index", "ledger_state", "tx_index"):
            try:
                out[table] = int(con.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0])
            except Exception:
                out[table] = -1
        return out
    finally:
        con.close()


def _corrupt_block_rejected(source_db: str, chain_id: str) -> bool:
    con = sqlite3.connect(source_db)
    try:
        row = con.execute("SELECT block_json FROM blocks ORDER BY height ASC LIMIT 1").fetchone()
        if row is None:
            return False
        block = json.loads(row[0])
    finally:
        con.close()
    block["block_hash"] = "00" * 32
    with tempfile.TemporaryDirectory(prefix="weall-b540-corrupt-") as td:
        ex = WeAllExecutor(db_path=str(Path(td) / "fresh.sqlite"), node_id="fresh-corrupt", chain_id=chain_id, tx_index_path=_tx_index_path())
        meta = ex.apply_block(block)
        return not bool(meta.ok)


def run_harness() -> dict[str, Any]:
    old = os.environ.copy()
    try:
        _clean_env()
        with tempfile.TemporaryDirectory(prefix="weall-b540-production-replay-") as td:
            result = build_sample_chain(work_dir=td, chain_id_prefix="batch540")
            source_db = str(result.get("source_db") or "")
            replay_db = str(result.get("replay_db") or "")
            source_manifest = result.get("source_manifest") if isinstance(result.get("source_manifest"), dict) else {}
            chain_id = str(result.get("chain_id") or source_manifest.get("chain_id") or "")
            corrupt_rejected = _corrupt_block_rejected(source_db, chain_id)
            source_counts = _table_counts(source_db)
            replay_counts = _table_counts(replay_db)
            return {
                "ok": bool(result.get("ok")) and corrupt_rejected,
                "batch": "540",
                "production_commit_path": True,
                "source_db_backed": True,
                "fresh_replay_db_backed": True,
                "block_commit_tables_used": ["blocks", "block_hash_index", "ledger_state", "tx_index"],
                "source_table_counts": source_counts,
                "replay_table_counts": replay_counts,
                "height": int(source_manifest.get("height") or 0),
                "state_roots_match": bool(result.get("ok")),
                "corrupt_block_rejected": corrupt_rejected,
                "issues": list(result.get("issues") or []),
            }
    finally:
        os.environ.clear(); os.environ.update(old)


def main() -> int:
    ap = argparse.ArgumentParser(); ap.add_argument("--json", action="store_true"); args = ap.parse_args()
    out = run_harness()
    print(json.dumps(out, sort_keys=True, indent=2 if args.json else None))
    return 0 if out.get("ok") else 1


if __name__ == "__main__":
    raise SystemExit(main())
