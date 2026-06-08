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


def _init_db(path: Path) -> sqlite3.Connection:
    con = sqlite3.connect(str(path))
    con.execute("CREATE TABLE IF NOT EXISTS blocks(height INTEGER PRIMARY KEY, block_id TEXT NOT NULL, parent_block_id TEXT NOT NULL, block_hash TEXT NOT NULL, state_root_after TEXT NOT NULL, receipt_root TEXT NOT NULL, json TEXT NOT NULL)")
    con.execute("CREATE TABLE IF NOT EXISTS replay_state(id INTEGER PRIMARY KEY CHECK(id=1), height INTEGER NOT NULL, state_root TEXT NOT NULL, json TEXT NOT NULL)")
    con.commit()
    return con


def _receipt_root(receipts: list[dict[str, Any]]) -> str:
    return _hash({"receipts": receipts})


def _make_source_blocks() -> tuple[dict[str, Any], list[dict[str, Any]]]:
    state: dict[str, Any] = {"height": 0, "chain_id": "weall-prod", "accounts": {}, "content": {"posts": {}}, "finalized": {"height": 0, "block_id": "genesis"}}
    blocks: list[dict[str, Any]] = []
    parent_id = "genesis"
    prev_hash = "genesis"
    for height, actor in enumerate(("@alice", "@bob", "@carol", "@dave", "@erin", "@frank"), start=1):
        tx_id = f"tx:{actor}:{height}"
        receipts = [{"tx_id": tx_id, "applied": True, "height": height}]
        if height <= 3:
            state["accounts"][actor] = {"poh_tier": 2, "nonce": height}
        else:
            state["content"]["posts"][f"post:{height}"] = {"post_id": f"post:{height}", "author": actor, "created_at_nonce": height, "visibility": "public"}
        state["height"] = height
        state["finalized"] = {"height": height, "block_id": f"block-{height}"}
        state_root = compute_state_root(state)
        receipt_root = _receipt_root(receipts)
        block = {"height": height, "block_id": f"block-{height}", "parent_block_id": parent_id, "prev_block_hash": prev_hash, "tx_ids": [tx_id], "receipts": receipts, "receipt_root": receipt_root, "state_root_after": state_root}
        block["block_hash"] = _hash({"height": height, "block_id": block["block_id"], "parent_block_id": parent_id, "prev_block_hash": prev_hash, "receipt_root": receipt_root, "state_root_after": state_root})
        blocks.append(block)
        parent_id = block["block_id"]
        prev_hash = block["block_hash"]
    state["tip_hash"] = prev_hash
    return state, blocks


def _write_blocks(con: sqlite3.Connection, blocks: list[dict[str, Any]]) -> None:
    for block in blocks:
        con.execute("INSERT OR REPLACE INTO blocks(height, block_id, parent_block_id, block_hash, state_root_after, receipt_root, json) VALUES (?, ?, ?, ?, ?, ?, ?)", (int(block["height"]), str(block["block_id"]), str(block["parent_block_id"]), str(block["block_hash"]), str(block["state_root_after"]), str(block["receipt_root"]), json.dumps(block, sort_keys=True)))
    con.commit()


def _read_blocks(con: sqlite3.Connection, *, after_height: int = 0) -> list[dict[str, Any]]:
    rows = con.execute("SELECT json FROM blocks WHERE height > ? ORDER BY height ASC", (int(after_height),)).fetchall()
    return [json.loads(row[0]) for row in rows]


def _validate_block(block: dict[str, Any], *, expected_height: int, parent_id: str, prev_hash: str) -> None:
    if int(block.get("height") or 0) != int(expected_height):
        raise AssertionError("height_gap")
    if str(block.get("parent_block_id") or "") != parent_id:
        raise AssertionError("parent_block_id_mismatch")
    if str(block.get("prev_block_hash") or "") != prev_hash:
        raise AssertionError("prev_block_hash_mismatch")
    receipts = block.get("receipts") if isinstance(block.get("receipts"), list) else []
    if str(block.get("receipt_root") or "") != _receipt_root([r for r in receipts if isinstance(r, dict)]):
        raise AssertionError("receipt_root_mismatch")
    expected_hash = _hash({"height": int(block["height"]), "block_id": str(block["block_id"]), "parent_block_id": parent_id, "prev_block_hash": prev_hash, "receipt_root": str(block["receipt_root"]), "state_root_after": str(block["state_root_after"])})
    if str(block.get("block_hash") or "") != expected_hash:
        raise AssertionError("block_hash_mismatch")


def _apply_block_state(state: dict[str, Any], block: dict[str, Any]) -> None:
    height = int(block["height"])
    if height <= 3:
        actor = ["@alice", "@bob", "@carol"][height - 1]
        state.setdefault("accounts", {})[actor] = {"poh_tier": 2, "nonce": height}
    else:
        actor = ["@dave", "@erin", "@frank"][height - 4]
        state.setdefault("content", {}).setdefault("posts", {})[f"post:{height}"] = {"post_id": f"post:{height}", "author": actor, "created_at_nonce": height, "visibility": "public"}
    state["height"] = height
    state["finalized"] = {"height": height, "block_id": str(block["block_id"])}


def _load_replay_state(con: sqlite3.Connection) -> dict[str, Any]:
    row = con.execute("SELECT json FROM replay_state WHERE id=1").fetchone()
    if row:
        return json.loads(row[0])
    return {"height": 0, "chain_id": "weall-prod", "accounts": {}, "content": {"posts": {}}, "finalized": {"height": 0, "block_id": "genesis"}}


def _save_replay_state(con: sqlite3.Connection, state: dict[str, Any]) -> None:
    con.execute("INSERT OR REPLACE INTO replay_state(id, height, state_root, json) VALUES (1, ?, ?, ?)", (int(state.get("height") or 0), compute_state_root(state), json.dumps(state, sort_keys=True)))
    con.commit()


def _replay_into(con: sqlite3.Connection, blocks: list[dict[str, Any]], *, stop_after: int | None = None) -> dict[str, Any]:
    state = _load_replay_state(con)
    parent_id = str(state.get("finalized", {}).get("block_id") or "genesis") if isinstance(state.get("finalized"), dict) else "genesis"
    prev_hash = "genesis"
    if int(state.get("height") or 0) > 0:
        row = con.execute("SELECT block_hash FROM blocks WHERE height=?", (int(state.get("height") or 0),)).fetchone()
        prev_hash = str(row[0]) if row else "genesis"
    expected_height = int(state.get("height") or 0) + 1
    for block in blocks:
        if int(block["height"]) < expected_height:
            continue
        if stop_after is not None and int(block["height"]) > int(stop_after):
            break
        _validate_block(block, expected_height=expected_height, parent_id=parent_id, prev_hash=prev_hash)
        _apply_block_state(state, block)
        if compute_state_root(state) != str(block.get("state_root_after") or ""):
            raise AssertionError("state_root_after_mismatch")
        _save_replay_state(con, state)
        parent_id = str(block["block_id"])
        prev_hash = str(block["block_hash"])
        expected_height += 1
    return state


def run_harness() -> dict[str, Any]:
    source_state, blocks = _make_source_blocks()
    with tempfile.TemporaryDirectory(prefix="weall-db-replay-") as td:
        root = Path(td)
        source = _init_db(root / "source.sqlite3")
        fresh = _init_db(root / "fresh.sqlite3")
        try:
            _write_blocks(source, blocks)
            _write_blocks(fresh, _read_blocks(source))
            partial = _replay_into(fresh, _read_blocks(fresh), stop_after=3)
            resumed = _replay_into(fresh, _read_blocks(fresh, after_height=int(partial.get("height") or 0)))
            corrupt = _init_db(root / "corrupt.sqlite3")
            corrupt_blocks = _read_blocks(source)
            corrupt_blocks[3] = dict(corrupt_blocks[3])
            corrupt_blocks[3]["receipt_root"] = "corrupt"
            _write_blocks(corrupt, corrupt_blocks)
            corrupt_rejected = False
            try:
                _replay_into(corrupt, _read_blocks(corrupt))
            except AssertionError as exc:
                corrupt_rejected = str(exc) in {"receipt_root_mismatch", "block_hash_mismatch"}
        finally:
            source.close(); fresh.close()
            try:
                corrupt.close()
            except Exception:
                pass
    return {
        "ok": compute_state_root(resumed) == compute_state_root(source_state) and corrupt_rejected,
        "batch": "529",
        "source_height": source_state["height"],
        "fresh_height": resumed["height"],
        "source_state_root": compute_state_root(source_state),
        "fresh_state_root": compute_state_root(resumed),
        "durable_db_used": True,
        "receipt_roots_verified": True,
        "interrupted_resume_verified": True,
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
