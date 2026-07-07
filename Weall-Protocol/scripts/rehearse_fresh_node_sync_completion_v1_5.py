#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from weall.net.messages import MsgType, StateSyncRequestMsg, WireHeader
from weall.net.state_sync import StateSyncService, build_snapshot_anchor
from weall.runtime.state_hash import compute_state_root

Json = dict[str, Any]
CHAIN_ID = "weall-v15-b510-fresh-node-sync"
SCHEMA_VERSION = "1"
TX_INDEX_HASH = "tx-index-b510"


def _header(corr_id: str) -> WireHeader:
    return WireHeader(type=MsgType.STATE_SYNC_REQUEST, chain_id=CHAIN_ID, schema_version=SCHEMA_VERSION, tx_index_hash=TX_INDEX_HASH, corr_id=corr_id)


def run_harness() -> Json:
    source_state: Json = {
        "state_version": 1,
        "height": 42,
        "chain_id": CHAIN_ID,
        "finalized": {"height": 42, "block_id": "block:42"},
        "accounts": {"alice": {"nonce": 7, "poh_tier": 2}, "bob": {"nonce": 1}},
        "roles": {"validators": {"active_set": ["validator-a", "validator-b", "validator-c", "validator-d"]}},
    }
    source_root = compute_state_root(source_state)
    trusted_anchor = build_snapshot_anchor(source_state)
    service = StateSyncService(
        chain_id=CHAIN_ID,
        schema_version=SCHEMA_VERSION,
        tx_index_hash=TX_INDEX_HASH,
        state_provider=lambda: source_state,
        require_trusted_anchor=True,
        enforce_finalized_anchor=True,
    )
    response = service.handle_request(StateSyncRequestMsg(header=_header("fresh-node"), mode="snapshot", selector={"trusted_anchor": trusted_anchor}))
    service.verify_response(response, trusted_anchor=trusted_anchor)
    fresh_node_state = dict(response.snapshot or {})
    fresh_root = compute_state_root(fresh_node_state)
    ok = bool(response.ok) and source_root == fresh_root and int(fresh_node_state.get("height") or 0) == 42
    return {
        "artifact": "b510_fresh_node_sync_completion_v1_5",
        "source_height": int(source_state["height"]),
        "fresh_height": int(fresh_node_state.get("height") or 0),
        "source_state_root": source_root,
        "fresh_state_root": fresh_root,
        "trusted_anchor_height": int(trusted_anchor.get("height") or 0),
        "verified": bool(response.ok),
        "ok": bool(ok),
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    out = run_harness()
    print(json.dumps(out, sort_keys=True, indent=None if args.json else 2))
    return 0 if out.get("ok") is True else 1


if __name__ == "__main__":
    raise SystemExit(main())
