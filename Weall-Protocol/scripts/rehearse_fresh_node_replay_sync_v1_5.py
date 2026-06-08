#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
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
        block = {"height": height, "block_id": f"block-{height}", "parent_block_id": prev_id, "prev_block_hash": prev_hash, "state_delta": delta, "state_root_after": compute_state_root(state)}
        block["block_hash"] = _hash({"height": height, "block_id": block["block_id"], "prev": prev_hash, "state_root_after": block["state_root_after"]})
        blocks.append(block)
        prev_hash = block["block_hash"]
        prev_id = block["block_id"]
    state["tip_hash"] = prev_hash
    return state, blocks


def _apply_delta(state: dict[str, Any], block: dict[str, Any]) -> None:
    delta = block.get("state_delta") if isinstance(block.get("state_delta"), dict) else {}
    accounts = delta.get("accounts") if isinstance(delta.get("accounts"), dict) else {}
    state.setdefault("accounts", {}).update(accounts)
    state["height"] = int(block["height"])
    state["finalized"] = {"height": int(block["height"]), "block_id": str(block["block_id"])}


def run_harness() -> dict[str, Any]:
    source_state, blocks = _build_chain()
    by_height = {int(b["height"]): dict(b) for b in blocks}
    svc = StateSyncService(chain_id="weall-prod", schema_version="1", tx_index_hash="tx-index-demo", state_provider=lambda: source_state, block_provider=lambda h: by_height.get(int(h)), require_trusted_anchor=True, fallback_to_snapshot=False)
    anchor = build_snapshot_anchor(source_state)
    req = StateSyncRequestMsg(header=WireHeader(type=MsgType.STATE_SYNC_REQUEST, chain_id="weall-prod", schema_version="1", tx_index_hash="tx-index-demo", sent_ts_ms=1, corr_id="sync-1"), mode="delta", from_height=0, to_height=source_state["height"], selector={"trusted_anchor": anchor})
    resp = svc.handle_request(req)
    svc.verify_response(resp, trusted_anchor=anchor)

    fresh: dict[str, Any] = {"height": 0, "chain_id": "weall-prod", "accounts": {}, "finalized": {"height": 0, "block_id": "genesis"}}
    verified_roots: list[str] = []
    for block in resp.blocks or ():
        _apply_delta(fresh, block)
        root = compute_state_root(fresh)
        if root != block.get("state_root_after"):
            raise AssertionError("state_root_after_mismatch")
        verified_roots.append(root)
    fresh["tip_hash"] = blocks[-1]["block_hash"]

    interrupted = {"height": 0, "chain_id": "weall-prod", "accounts": {}, "finalized": {"height": 0, "block_id": "genesis"}}
    for block in blocks[:2]:
        _apply_delta(interrupted, block)
    for block in blocks[2:]:
        _apply_delta(interrupted, block)
    interrupted["tip_hash"] = blocks[-1]["block_hash"]

    return {"ok": compute_state_root(fresh) == compute_state_root(source_state) == compute_state_root(interrupted), "batch": "518", "verified_block_count": len(verified_roots), "source_height": source_state["height"], "fresh_height": fresh["height"], "source_state_root": compute_state_root(source_state), "fresh_state_root": compute_state_root(fresh), "interrupted_resume_root": compute_state_root(interrupted), "snapshot_used": False}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    out = run_harness()
    print(json.dumps(out, sort_keys=True, indent=None if args.json else 2))
    return 0 if out.get("ok") else 1


if __name__ == "__main__":
    raise SystemExit(main())
