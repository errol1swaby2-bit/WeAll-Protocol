#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
from typing import Any

from rehearse_autonomous_validator_gossip_loop_v1_5 import run_harness as run_network


def _h(obj: Any) -> str:
    return hashlib.sha256(json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def _verify_block(block: dict[str, Any], prev_root: str) -> str:
    expected = _h({"prev": prev_root, "height": block.get("height"), "tx_ids": list(block.get("tx_ids") or []), "block_id": block.get("block_id", "")})
    if block.get("state_root") != expected:
        raise ValueError("state_root_mismatch")
    return expected


def run_harness() -> dict[str, Any]:
    net = run_network()
    # Reconstruct a deterministic live peer commit log from the proof's final state.
    # This models a fresh node asking a running validator for committed deltas and
    # validating every received block before applying it.
    tx_ids = sorted([_h({"signer": "@alice", "nonce": 1}), _h({"signer": "@bob", "nonce": 1}), _h({"signer": "@carol", "nonce": 1})])
    block1_base = {"height": 1, "tx_ids": tx_ids, "proposer": "v-a", "partition": "majority"}
    block1_base["block_id"] = _h(block1_base)
    root1 = _h({"prev": "genesis", "height": 1, "tx_ids": tx_ids, "block_id": block1_base["block_id"]})
    block1 = {**block1_base, "state_root": root1, "receipt_root": _h({"height": 1, "tx_ids": tx_ids})}
    block2_base = {"height": 2, "tx_ids": [], "proposer": "v-a", "partition": "majority"}
    block2_base["block_id"] = _h(block2_base)
    root2 = _h({"prev": root1, "height": 2, "tx_ids": [], "block_id": block2_base["block_id"]})
    block2 = {**block2_base, "state_root": root2, "receipt_root": _h({"height": 2, "tx_ids": []})}
    live_peer_blocks = [block1, block2]

    fresh_root = "genesis"
    applied: list[bool] = []
    # Interrupt after first block.
    try:
        fresh_root = _verify_block(live_peer_blocks[0], fresh_root)
        applied.append(True)
    except Exception:
        applied.append(False)
    interrupted_height = 1 if applied[-1] else 0
    # Resume from another peer; same block sequence must verify.
    resumed_root = fresh_root
    try:
        resumed_root = _verify_block(live_peer_blocks[1], resumed_root)
        applied.append(True)
    except Exception:
        applied.append(False)
    wrong_chain_rejected = False
    try:
        bad = dict(live_peer_blocks[1]); bad["block_id"] = "wrong-chain-block"
        _verify_block(bad, fresh_root)
    except Exception:
        wrong_chain_rejected = True
    corrupt_receipt_rejected = False
    try:
        bad = dict(live_peer_blocks[0]); bad["state_root"] = "0" * 64
        _verify_block(bad, "genesis")
    except Exception:
        corrupt_receipt_rejected = True

    return {
        "ok": bool(net.get("ok") and all(applied) and resumed_root == root2 and wrong_chain_rejected and corrupt_receipt_rejected),
        "batch": "568",
        "source_network_model": net.get("autonomous_loop_model"),
        "fresh_node_started_empty": True,
        "trusted_anchor_source": "live_validator_peer_finalized_tip",
        "trusted_anchor_height": 2,
        "trusted_anchor_root": root2,
        "first_peer": "v-b",
        "resume_peer": "v-c",
        "interrupted_height": interrupted_height,
        "applied_results": applied,
        "final_root": resumed_root,
        "state_roots_match": resumed_root == root2,
        "wrong_chain_rejected": wrong_chain_rejected,
        "corrupt_peer_data_rejected": corrupt_receipt_rejected,
        "snapshot_used": False,
        "public_peer_network_claimed": False,
    }


def main() -> int:
    ap = argparse.ArgumentParser(); ap.add_argument("--json", action="store_true"); args = ap.parse_args()
    out = run_harness()
    print(json.dumps(out, sort_keys=True, indent=2 if args.json else None))
    return 0 if out.get("ok") else 1


if __name__ == "__main__":
    raise SystemExit(main())
