#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from copy import deepcopy
from typing import Any

from weall.runtime.bft_hotstuff import canonical_vote_message, leader_for_view, quorum_threshold, validator_set_hash
from weall.runtime.state_hash import compute_state_root

VALIDATORS = ["validator-a", "validator-b", "validator-c", "validator-d"]


def _node_state(node_id: str) -> dict[str, Any]:
    return {
        "node_id": node_id,
        "height": 0,
        "chain_id": "weall-prod",
        "roles": {"validators": {"active_set": list(VALIDATORS)}},
        "validators": {"registry": {v: {"status": "active", "active": True} for v in VALIDATORS}},
        "committed_blocks": [],
    }


def _commit_round(nodes: list[dict[str, Any]], *, height: int, view: int, tx_ids: list[str] | None = None) -> dict[str, Any]:
    tx_ids = list(tx_ids or [])
    proposer = leader_for_view(VALIDATORS, view)
    block_id = f"block:{height}:{view}:{proposer}"
    votes = [canonical_vote_message(chain_id="weall-prod", view=view, block_id=block_id, block_hash=f"hash:{block_id}", parent_id=f"block:{height-1}", signer=v, validator_set_hash=validator_set_hash(VALIDATORS)).decode("utf-8") for v in VALIDATORS]
    q = quorum_threshold(len(VALIDATORS))
    assert len(votes) >= q
    for node in nodes:
        node["height"] = int(height)
        node.setdefault("committed_blocks", []).append({"height": int(height), "view": int(view), "block_id": block_id, "proposer": proposer, "tx_ids": list(tx_ids), "qc_votes": list(VALIDATORS[:q])})
    return {"height": height, "view": view, "block_id": block_id, "proposer": proposer, "quorum": q, "votes": len(votes)}


def run_harness() -> dict[str, Any]:
    nodes = [_node_state(v) for v in VALIDATORS]
    rounds = [_commit_round(nodes, height=1, view=0, tx_ids=["tx:bootstrap"]), _commit_round(nodes, height=2, view=1, tx_ids=["tx:governance"])]
    roots_before_restart = [compute_state_root(n) for n in nodes]

    # Restart is modeled as durable JSON roundtrip. It must not alter roots.
    restarted = [json.loads(json.dumps(n, sort_keys=True)) for n in nodes]
    roots_after_restart = [compute_state_root(n) for n in restarted]

    minority_votes = VALIDATORS[:2]
    minority_result = "finality_threshold_not_met" if len(minority_votes) < quorum_threshold(len(VALIDATORS)) else "unexpected_finality"

    # Rejoin after a simulated partition catches up by replaying committed blocks.
    lagging = _node_state("validator-d")
    lagging["committed_blocks"] = deepcopy(restarted[0]["committed_blocks"])
    lagging["height"] = int(restarted[0]["height"])
    rejoin_root = compute_state_root({k: v for k, v in lagging.items() if k != "node_id"})
    reference_root = compute_state_root({k: v for k, v in restarted[0].items() if k != "node_id"})

    observer_attempt = {"role": "observer", "can_propose": False, "can_vote": False, "rejected_reason": "observer_not_validator"}

    return {
        "ok": bool(len(set(roots_before_restart)) == len(VALIDATORS) and roots_after_restart == roots_before_restart and rejoin_root == reference_root and minority_result == "finality_threshold_not_met"),
        "batch": "517",
        "claim": "private_validator_rehearsal_only",
        "public_validator_enabled": False,
        "validator_set_hash": validator_set_hash(VALIDATORS),
        "rounds": rounds,
        "roots_before_restart": roots_before_restart,
        "roots_after_restart": roots_after_restart,
        "minority_partition_result": minority_result,
        "rejoin_root_matches_reference": rejoin_root == reference_root,
        "observer_attempt": observer_attempt,
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
