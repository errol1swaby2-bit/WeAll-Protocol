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

from weall.net.messages import MsgType, StateSyncRequestMsg, StateSyncResponseMsg, WireHeader
from weall.net.state_sync import StateSyncService, StateSyncVerifyError, build_snapshot_anchor, sha256_hex_of

Json = dict[str, Any]
CHAIN_ID = "weall-v15-b506-state-sync-adversarial"
SCHEMA_VERSION = "1"
TX_INDEX_HASH = "tx-index-b506"


def _header(corr_id: str) -> WireHeader:
    return WireHeader(type=MsgType.STATE_SYNC_REQUEST, chain_id=CHAIN_ID, schema_version=SCHEMA_VERSION, tx_index_hash=TX_INDEX_HASH, corr_id=corr_id)


def _response_header(corr_id: str) -> WireHeader:
    return WireHeader(type=MsgType.STATE_SYNC_RESPONSE, chain_id=CHAIN_ID, schema_version=SCHEMA_VERSION, tx_index_hash=TX_INDEX_HASH, corr_id=corr_id)


def _verify_error(fn) -> str:
    try:
        fn()
    except StateSyncVerifyError as exc:
        return str(exc)
    return ""


def run_harness() -> Json:
    state: Json = {
        "state_version": 1,
        "height": 18,
        "tip_hash": "tip:18",
        "finalized": {"height": 18, "block_id": "block:18"},
        "accounts": {"alice": {"nonce": 3}, "bob": {"nonce": 4}},
    }
    anchor = build_snapshot_anchor(state)
    service = StateSyncService(
        chain_id=CHAIN_ID,
        schema_version=SCHEMA_VERSION,
        tx_index_hash=TX_INDEX_HASH,
        state_provider=lambda: state,
        require_trusted_anchor=True,
        enforce_finalized_anchor=True,
    )
    good = service.handle_request(StateSyncRequestMsg(header=_header("good"), mode="snapshot", selector={"trusted_anchor": anchor}))
    service.verify_response(good, trusted_anchor=anchor)

    bad_anchor = service.handle_request(StateSyncRequestMsg(header=_header("bad-anchor"), mode="snapshot", selector={"trusted_anchor": {**anchor, "state_root": "bad-root"}}))

    corrupt_snapshot = copy.deepcopy(good.snapshot or {})
    corrupt_snapshot.setdefault("accounts", {})["mallory"] = {"nonce": 999}
    corrupt_response = StateSyncResponseMsg(
        header=_response_header("corrupt-snapshot"),
        ok=True,
        reason=None,
        height=int(good.height),
        snapshot=corrupt_snapshot,
        snapshot_hash=good.snapshot_hash,
        snapshot_anchor=good.snapshot_anchor,
    )
    corrupt_reason = _verify_error(lambda: service.verify_response(corrupt_response, trusted_anchor=anchor))

    stale_anchor_response = StateSyncResponseMsg(
        header=_response_header("stale-anchor"),
        ok=True,
        reason=None,
        height=int(good.height),
        snapshot=good.snapshot,
        snapshot_hash=sha256_hex_of(good.snapshot),
        snapshot_anchor={**(good.snapshot_anchor or {}), "height": 17},
    )
    stale_reason = _verify_error(lambda: service.verify_response(stale_anchor_response, trusted_anchor=anchor))

    ok = bool(good.ok) and bad_anchor.ok is False and bad_anchor.reason == "trusted_anchor_mismatch" and corrupt_reason == "snapshot_hash_mismatch" and stale_reason.startswith("trusted_anchor_mismatch")
    return {
        "artifact": "b506_state_sync_adversarial_proof_v1_5",
        "good_snapshot_verified": bool(good.ok),
        "invalid_anchor_rejected": bad_anchor.ok is False and bad_anchor.reason == "trusted_anchor_mismatch",
        "corrupt_snapshot_rejected": corrupt_reason == "snapshot_hash_mismatch",
        "corrupt_snapshot_reason": corrupt_reason,
        "stale_anchor_rejected": stale_reason.startswith("trusted_anchor_mismatch"),
        "stale_anchor_reason": stale_reason,
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
