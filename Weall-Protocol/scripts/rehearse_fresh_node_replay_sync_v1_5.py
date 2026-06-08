#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import tempfile
from pathlib import Path
from typing import Any

from weall.net.messages import MsgType, StateSyncRequestMsg, WireHeader
from weall.net.state_sync import StateSyncService, build_snapshot_anchor
from weall.runtime.state_hash import compute_state_root


def _hash(obj: Any) -> str:
    return hashlib.sha256(json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def _build_chain() -> tuple[dict[str, Any], list[dict[str, Any]]]:
    state: dict[str, Any] = {"height": 0, "chain_id": "weall-prod", "accounts": {}, "finalized": {"height": 0, "block_id": "genesis"}}
    blocks: list[dict[str, Any]] = []
    prev_hash = "genesis"
    prev_id = "genesis"
    for height, account in enumerate(("alice", "bob", "carol", "dave", "erin"), start=1):
        delta = {"accounts": {account: {"poh_tier": 1, "balance": 0}}}
        state["accounts"].update(delta["accounts"])
        state["height"] = height
        state["finalized"] = {"height": height, "block_id": f"block-{height}"}
        block = {
            "height": height,
            "block_id": f"block-{height}",
            "parent_block_id": prev_id,
            "prev_block_hash": prev_hash,
            "state_delta": delta,
            "state_root_after": compute_state_root(state),
        }
        block["block_hash"] = _hash({"height": height, "block_id": block["block_id"], "prev": prev_hash, "state_root_after": block["state_root_after"]})
        blocks.append(block)
        prev_hash = block["block_hash"]
        prev_id = block["block_id"]
    state["tip_hash"] = prev_hash
    return state, blocks


def _write_block_store(root: Path, blocks: list[dict[str, Any]]) -> None:
    root.mkdir(parents=True, exist_ok=True)
    for block in blocks:
        (root / f"{int(block['height']):08d}.json").write_text(json.dumps(block, sort_keys=True), encoding="utf-8")


def _read_block_store(root: Path) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for path in sorted(root.glob("*.json")):
        out.append(json.loads(path.read_text(encoding="utf-8")))
    return out


def _validate_block_sequence(blocks: list[dict[str, Any]]) -> None:
    prev_hash = "genesis"
    prev_id = "genesis"
    expected_height = 1
    for block in blocks:
        height = int(block.get("height") or 0)
        if height != expected_height:
            raise AssertionError("non_contiguous_height")
        if str(block.get("parent_block_id") or "") != prev_id:
            raise AssertionError("parent_block_id_mismatch")
        if str(block.get("prev_block_hash") or "") != prev_hash:
            raise AssertionError("prev_block_hash_mismatch")
        expected_hash = _hash({"height": height, "block_id": str(block.get("block_id") or ""), "prev": prev_hash, "state_root_after": str(block.get("state_root_after") or "")})
        if str(block.get("block_hash") or "") != expected_hash:
            raise AssertionError("block_hash_mismatch")
        prev_hash = str(block.get("block_hash") or "")
        prev_id = str(block.get("block_id") or "")
        expected_height += 1


def _apply_delta(state: dict[str, Any], block: dict[str, Any]) -> None:
    delta = block.get("state_delta") if isinstance(block.get("state_delta"), dict) else {}
    accounts = delta.get("accounts") if isinstance(delta.get("accounts"), dict) else {}
    state.setdefault("accounts", {}).update(accounts)
    state["height"] = int(block["height"])
    state["finalized"] = {"height": int(block["height"]), "block_id": str(block["block_id"])}


def _replay(blocks: list[dict[str, Any]], *, stop_after: int | None = None, state: dict[str, Any] | None = None) -> dict[str, Any]:
    st = state if isinstance(state, dict) else {"height": 0, "chain_id": "weall-prod", "accounts": {}, "finalized": {"height": 0, "block_id": "genesis"}}
    for block in blocks:
        if stop_after is not None and int(block["height"]) > int(stop_after):
            break
        _apply_delta(st, block)
        root = compute_state_root(st)
        if root != block.get("state_root_after"):
            raise AssertionError("state_root_after_mismatch")
    if blocks:
        st["tip_hash"] = str(blocks[min(len(blocks), int(st.get("height") or 0)) - 1]["block_hash"])
    return st


def run_harness() -> dict[str, Any]:
    source_state, blocks = _build_chain()
    by_height = {int(b["height"]): dict(b) for b in blocks}
    svc = StateSyncService(chain_id="weall-prod", schema_version="1", tx_index_hash="tx-index-demo", state_provider=lambda: source_state, block_provider=lambda h: by_height.get(int(h)), require_trusted_anchor=True, fallback_to_snapshot=False)
    anchor = build_snapshot_anchor(source_state)
    req = StateSyncRequestMsg(header=WireHeader(type=MsgType.STATE_SYNC_REQUEST, chain_id="weall-prod", schema_version="1", tx_index_hash="tx-index-demo", sent_ts_ms=1, corr_id="sync-1"), mode="delta", from_height=0, to_height=source_state["height"], selector={"trusted_anchor": anchor})
    resp = svc.handle_request(req)
    svc.verify_response(resp, trusted_anchor=anchor)

    with tempfile.TemporaryDirectory(prefix="weall-replay-sync-") as td:
        store = Path(td) / "blocks"
        _write_block_store(store, list(resp.blocks or ()))
        durable_blocks = _read_block_store(store)
        _validate_block_sequence(durable_blocks)
        fresh = _replay(durable_blocks)

        interrupted = _replay(durable_blocks, stop_after=2)
        resumed = _replay([b for b in durable_blocks if int(b["height"]) > 2], state=interrupted)

        corrupt_store = Path(td) / "corrupt"
        _write_block_store(corrupt_store, durable_blocks)
        corrupt_path = corrupt_store / "00000003.json"
        corrupt = json.loads(corrupt_path.read_text(encoding="utf-8"))
        corrupt["state_root_after"] = "corrupt-root"
        corrupt_path.write_text(json.dumps(corrupt, sort_keys=True), encoding="utf-8")
        corrupt_rejected = False
        try:
            _validate_block_sequence(_read_block_store(corrupt_store))
        except AssertionError as exc:
            corrupt_rejected = str(exc) == "block_hash_mismatch"

    return {
        "ok": compute_state_root(fresh) == compute_state_root(source_state) == compute_state_root(resumed) and corrupt_rejected,
        "batch": "524",
        "verified_block_count": len(blocks),
        "source_height": source_state["height"],
        "fresh_height": fresh["height"],
        "source_state_root": compute_state_root(source_state),
        "fresh_state_root": compute_state_root(fresh),
        "interrupted_resume_root": compute_state_root(resumed),
        "snapshot_used": False,
        "durable_block_store_used": True,
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
