#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import sqlite3
import tempfile
from pathlib import Path
from typing import Any

from weall.runtime.state_hash import compute_state_root


def _hash(obj: Any) -> str:
    return hashlib.sha256(json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def _canon(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"))


def _init_node_db(path: Path) -> sqlite3.Connection:
    con = sqlite3.connect(str(path))
    con.execute("CREATE TABLE IF NOT EXISTS blocks(height INTEGER PRIMARY KEY, block_id TEXT NOT NULL, block_hash TEXT NOT NULL, block_json TEXT NOT NULL)")
    con.execute("CREATE TABLE IF NOT EXISTS block_hash_index(block_id TEXT PRIMARY KEY, block_hash TEXT NOT NULL, height INTEGER NOT NULL)")
    con.execute("CREATE TABLE IF NOT EXISTS ledger_state(id INTEGER PRIMARY KEY CHECK(id=1), height INTEGER NOT NULL, block_id TEXT NOT NULL, state_json TEXT NOT NULL)")
    con.commit()
    return con


def _receipt_root(receipts: list[dict[str, Any]]) -> str:
    return _hash({"receipts": receipts})


def _make_block(height: int, parent_id: str, prev_hash: str, state: dict[str, Any], tx_id: str) -> dict[str, Any]:
    receipts = [{"tx_id": tx_id, "ok": True, "height": int(height), "tx_type": "REHEARSAL_TX"}]
    receipt_root = _receipt_root(receipts)
    state_root = compute_state_root(state)
    block = {
        "height": int(height),
        "block_id": f"block-{height}",
        "parent_block_id": parent_id,
        "prev_block_hash": prev_hash,
        "receipt_root": receipt_root,
        "receipts": receipts,
        "state_root_after": state_root,
        "tx_ids": [tx_id],
    }
    block["block_hash"] = _hash({"height": height, "block_id": block["block_id"], "parent_block_id": parent_id, "prev_block_hash": prev_hash, "receipt_root": receipt_root, "state_root_after": state_root})
    return block


def _insert_committed(con: sqlite3.Connection, block: dict[str, Any], state: dict[str, Any]) -> None:
    con.execute("INSERT INTO blocks(height, block_id, block_hash, block_json) VALUES (?, ?, ?, ?)", (int(block["height"]), str(block["block_id"]), str(block["block_hash"]), _canon(block)))
    con.execute("INSERT INTO block_hash_index(block_id, block_hash, height) VALUES (?, ?, ?)", (str(block["block_id"]), str(block["block_hash"]), int(block["height"])))
    con.execute("INSERT OR REPLACE INTO ledger_state(id, height, block_id, state_json) VALUES (1, ?, ?, ?)", (int(state["height"]), str(block["block_id"]), _canon(state)))
    con.commit()


def _build_source(con: sqlite3.Connection) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    state: dict[str, Any] = {"chain_id": "weall-prod", "height": 0, "accounts": {}, "content": {"posts": {}}, "finalized": {"height": 0, "block_id": "genesis"}}
    parent = "genesis"
    prev_hash = "genesis"
    blocks: list[dict[str, Any]] = []
    for height in range(1, 8):
        if height <= 3:
            account = f"@user{height}"
            state["accounts"][account] = {"nonce": height, "poh_tier": 2}
            tx_id = f"tx:account:{height}"
        else:
            post_id = f"post:{height}"
            state["content"]["posts"][post_id] = {"post_id": post_id, "author": f"@user{height-3}", "created_at_nonce": height, "visibility": "public"}
            tx_id = f"tx:post:{height}"
        state["height"] = height
        state["finalized"] = {"height": height, "block_id": f"block-{height}"}
        block = _make_block(height, parent, prev_hash, state, tx_id)
        _insert_committed(con, block, state)
        blocks.append(block)
        parent = str(block["block_id"])
        prev_hash = str(block["block_hash"])
    state["tip_hash"] = prev_hash
    con.execute("INSERT OR REPLACE INTO ledger_state(id, height, block_id, state_json) VALUES (1, ?, ?, ?)", (int(state["height"]), str(state["finalized"]["block_id"]), _canon(state)))
    con.commit()
    return state, blocks


def _read_blocks(con: sqlite3.Connection, after_height: int = 0) -> list[dict[str, Any]]:
    rows = con.execute("SELECT block_json FROM blocks WHERE height > ? ORDER BY height ASC", (int(after_height),)).fetchall()
    return [json.loads(row[0]) for row in rows]


def _load_state(con: sqlite3.Connection) -> dict[str, Any]:
    row = con.execute("SELECT state_json FROM ledger_state WHERE id=1").fetchone()
    if row:
        return json.loads(row[0])
    return {"chain_id": "weall-prod", "height": 0, "accounts": {}, "content": {"posts": {}}, "finalized": {"height": 0, "block_id": "genesis"}}


def _validate_block(block: dict[str, Any], *, expected_height: int, parent: str, prev_hash: str) -> None:
    if int(block.get("height") or 0) != int(expected_height):
        raise AssertionError("height_gap")
    if str(block.get("parent_block_id") or "") != parent:
        raise AssertionError("parent_mismatch")
    if str(block.get("prev_block_hash") or "") != prev_hash:
        raise AssertionError("prev_hash_mismatch")
    receipts = [r for r in (block.get("receipts") if isinstance(block.get("receipts"), list) else []) if isinstance(r, dict)]
    if str(block.get("receipt_root") or "") != _receipt_root(receipts):
        raise AssertionError("receipt_root_mismatch")
    expected_hash = _hash({"height": int(block["height"]), "block_id": str(block["block_id"]), "parent_block_id": parent, "prev_block_hash": prev_hash, "receipt_root": str(block["receipt_root"]), "state_root_after": str(block["state_root_after"])})
    if str(block.get("block_hash") or "") != expected_hash:
        raise AssertionError("block_hash_mismatch")


def _apply_block(state: dict[str, Any], block: dict[str, Any]) -> None:
    height = int(block["height"])
    if height <= 3:
        state.setdefault("accounts", {})[f"@user{height}"] = {"nonce": height, "poh_tier": 2}
    else:
        post_id = f"post:{height}"
        state.setdefault("content", {}).setdefault("posts", {})[post_id] = {"post_id": post_id, "author": f"@user{height-3}", "created_at_nonce": height, "visibility": "public"}
    state["height"] = height
    state["finalized"] = {"height": height, "block_id": str(block["block_id"])}


def _commit_replayed(con: sqlite3.Connection, block: dict[str, Any], state: dict[str, Any]) -> None:
    _insert_committed(con, block, state)


def _replay_from_source(source: sqlite3.Connection, fresh: sqlite3.Connection, *, stop_after: int | None = None) -> dict[str, Any]:
    state = _load_state(fresh)
    start_height = int(state.get("height") or 0)
    parent = str(state.get("finalized", {}).get("block_id") or "genesis") if isinstance(state.get("finalized"), dict) else "genesis"
    if start_height:
        row = fresh.execute("SELECT block_hash FROM blocks WHERE height=?", (start_height,)).fetchone()
        prev_hash = str(row[0]) if row else "genesis"
    else:
        prev_hash = "genesis"
    expected = start_height + 1
    for block in _read_blocks(source, after_height=start_height):
        if stop_after is not None and int(block["height"]) > int(stop_after):
            break
        _validate_block(block, expected_height=expected, parent=parent, prev_hash=prev_hash)
        _apply_block(state, block)
        if compute_state_root(state) != str(block.get("state_root_after") or ""):
            raise AssertionError("state_root_after_mismatch")
        _commit_replayed(fresh, block, state)
        parent = str(block["block_id"])
        prev_hash = str(block["block_hash"])
        expected += 1
    return state


def run_harness() -> dict[str, Any]:
    with tempfile.TemporaryDirectory(prefix="weall-real-db-replay-") as td:
        root = Path(td)
        source = _init_node_db(root / "source.sqlite3")
        fresh = _init_node_db(root / "fresh.sqlite3")
        corrupt = _init_node_db(root / "corrupt.sqlite3")
        try:
            source_state, _blocks = _build_source(source)
            partial = _replay_from_source(source, fresh, stop_after=4)
            resumed = _replay_from_source(source, fresh)
            for block in _read_blocks(source):
                if int(block["height"]) == 5:
                    block = dict(block)
                    block["receipt_root"] = "corrupt"
                corrupt.execute("INSERT INTO blocks(height, block_id, block_hash, block_json) VALUES (?, ?, ?, ?)", (int(block["height"]), str(block["block_id"]), str(block["block_hash"]), _canon(block)))
            corrupt.commit()
            corrupt_fresh = _init_node_db(root / "corrupt-fresh.sqlite3")
            corrupt_rejected = False
            try:
                _replay_from_source(corrupt, corrupt_fresh)
            except AssertionError as exc:
                corrupt_rejected = str(exc) in {"receipt_root_mismatch", "block_hash_mismatch"}
            source_final = _load_state(source)
        finally:
            source.close(); fresh.close(); corrupt.close()
            try:
                corrupt_fresh.close()
            except Exception:
                pass
    return {
        "ok": compute_state_root(source_final) == compute_state_root(resumed) and corrupt_rejected,
        "batch": "535",
        "source_height": int(source_final["height"]),
        "fresh_height": int(resumed["height"]),
        "source_state_root": compute_state_root(source_final),
        "fresh_state_root": compute_state_root(resumed),
        "source_db_backed": True,
        "fresh_db_backed": True,
        "block_commit_tables_used": ["blocks", "block_hash_index", "ledger_state"],
        "receipt_roots_verified": True,
        "block_hashes_verified": True,
        "interrupted_resume_verified": int(partial.get("height") or 0) == 4,
        "corrupt_block_rejected": corrupt_rejected,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    out = run_harness()
    print(json.dumps(out, sort_keys=True, indent=None if args.json else 2))
    return 0 if out.get("ok") else 1


if __name__ == "__main__":
    raise SystemExit(main())
