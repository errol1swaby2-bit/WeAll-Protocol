#!/usr/bin/env python3
from __future__ import annotations

import argparse
import copy
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


def _header(corr_id: str = "b500") -> WireHeader:
    return WireHeader(
        type=MsgType.STATE_SYNC_REQUEST,
        chain_id="weall-v15-state-sync-proof",
        schema_version="1",
        tx_index_hash="tx-index-proof-hash",
        corr_id=corr_id,
    )


def run_harness() -> Json:
    source_state: Json = {
        "state_version": 1,
        "height": 12,
        "tip_hash": "tip:12",
        "finalized": {"height": 12, "block_id": "block:12"},
        "accounts": {
            "alice": {"nonce": 2, "poh_tier": 2},
            "bob": {"nonce": 1, "poh_tier": 1},
        },
        "params": {"chain_id": "weall-v15-state-sync-proof"},
    }
    trusted_anchor = build_snapshot_anchor(source_state)
    service = StateSyncService(
        chain_id="weall-v15-state-sync-proof",
        schema_version="1",
        tx_index_hash="tx-index-proof-hash",
        state_provider=lambda: source_state,
        require_trusted_anchor=True,
        enforce_finalized_anchor=True,
    )
    request = StateSyncRequestMsg(
        header=_header(),
        mode="snapshot",
        selector={"trusted_anchor": trusted_anchor},
    )
    response = service.handle_request(request)
    service.verify_response(response, trusted_anchor=trusted_anchor)

    fresh_node_state = copy.deepcopy(response.snapshot or {})
    source_root = compute_state_root(source_state)
    fresh_root = compute_state_root(fresh_node_state)

    bad_request = StateSyncRequestMsg(
        header=_header("b500-bad"),
        mode="snapshot",
        selector={"trusted_anchor": {**trusted_anchor, "state_root": "bad-root"}},
    )
    bad_response = service.handle_request(bad_request)

    ok = bool(response.ok) and source_root == fresh_root and bad_response.ok is False and bad_response.reason == "trusted_anchor_mismatch"
    return {
        "artifact": "fresh_node_state_sync_proof_v1_5",
        "source_height": int(source_state["height"]),
        "trusted_anchor_height": int(trusted_anchor["height"]),
        "trusted_anchor_finalized_height": int(trusted_anchor["finalized_height"]),
        "source_state_root": source_root,
        "fresh_node_state_root": fresh_root,
        "same_state_root": source_root == fresh_root,
        "bad_anchor_rejected": bad_response.ok is False and bad_response.reason == "trusted_anchor_mismatch",
        "ok": ok,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--json", action="store_true", help="print compact JSON")
    args = parser.parse_args()
    out = run_harness()
    print(json.dumps(out, sort_keys=True, indent=None if args.json else 2))
    return 0 if out.get("ok") is True else 1


if __name__ == "__main__":
    raise SystemExit(main())
