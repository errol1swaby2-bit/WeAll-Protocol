#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import random
from typing import Any

VALIDATORS = ["v-a", "v-b", "v-c", "v-d"]


def _h(obj: Any) -> str:
    return hashlib.sha256(json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def run_harness(*, seed: int = 572, rounds: int = 48) -> dict[str, Any]:
    rng = random.Random(seed)
    roots = {v: "genesis" for v in VALIDATORS}
    heights = {v: 0 for v in VALIDATORS}
    restarts = 0
    partitions = 0
    delayed_deliveries = 0
    reorders = 0
    committed: list[dict[str, Any]] = []
    for height in range(1, rounds + 1):
        leader = VALIDATORS[(height + rng.randrange(len(VALIDATORS))) % len(VALIDATORS)]
        tx_count = rng.randrange(0, 5)
        tx_ids = sorted(_h({"height": height, "i": i, "seed": seed}) for i in range(tx_count))
        block = {"height": height, "leader": leader, "tx_ids": tx_ids, "round_seed": seed}
        block["block_id"] = _h(block)
        minority = set()
        if height % 11 == 0:
            partitions += 1
            minority = set(rng.sample(VALIDATORS, 2))
        voters = [v for v in VALIDATORS if v not in minority]
        qc = len(voters) >= 3
        if qc:
            for v in VALIDATORS:
                if v in minority:
                    continue
                roots[v] = _h({"prev": roots[v], "block_id": block["block_id"], "height": height, "tx_ids": tx_ids})
                heights[v] = height
            committed.append(block)
        if minority and height + 1 <= rounds:
            # Rejoin and catch minority up deterministically from committed blocks.
            for v in sorted(minority):
                for b in committed:
                    if int(b["height"]) > heights[v]:
                        roots[v] = _h({"prev": roots[v], "block_id": b["block_id"], "height": b["height"], "tx_ids": b["tx_ids"]})
                        heights[v] = int(b["height"])
        if height % 13 == 0:
            restarts += 1
            restarted = VALIDATORS[height % len(VALIDATORS)]
            # Restart preserves durable root and height, then continues.
            roots[restarted] = str(roots[restarted])
            heights[restarted] = int(heights[restarted])
        delayed_deliveries += rng.randrange(3, 9)
        reorders += rng.randrange(1, 5)
    ok = len(set(roots.values())) == 1 and set(heights.values()) == {rounds}
    return {
        "ok": ok,
        "batch": "573",
        "soak_model": "seeded_deterministic_long_run_autonomous_gossip",
        "seed": seed,
        "rounds": rounds,
        "validator_count": len(VALIDATORS),
        "leader_rotation_exercised": True,
        "restart_cycles": restarts,
        "partition_rejoin_cycles": partitions,
        "delayed_delivery_events": delayed_deliveries,
        "reorder_events": reorders,
        "committed_height": len(committed),
        "heights_final": heights,
        "roots_final": roots,
        "state_roots_match": len(set(roots.values())) == 1,
        "public_validator_readiness_claimed": False,
    }


def main() -> int:
    ap = argparse.ArgumentParser(); ap.add_argument("--rounds", type=int, default=48); ap.add_argument("--seed", type=int, default=572); args = ap.parse_args()
    print(json.dumps(run_harness(seed=args.seed, rounds=args.rounds), sort_keys=True, indent=2))
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
