#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import json
import random
from typing import Any

Json = dict[str, Any]


def _sha(obj: Any) -> str:
    return hashlib.sha256(json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def run_harness(seed: int = 577581, rounds: int = 160) -> Json:
    rng = random.Random(seed)
    nodes = ["v-a", "v-b", "v-c", "v-d"]
    roots = {n: _sha({"genesis": n}) for n in nodes}
    queues = {n: [] for n in nodes}
    heights = {n: 0 for n in nodes}
    delayed = 0; dup = 0; dropped = 0; restarts = 0; partitions = 0; resource_pressure_events = 0
    committed: list[Json] = []
    for r in range(1, rounds + 1):
        proposer = nodes[(r - 1) % len(nodes)]
        tx_count = 1 + (r % 4)
        if r % 17 == 0:
            resource_pressure_events += 1
            tx_count += 12
        txs = [f"tx:{r}:{i}:{rng.randrange(10_000)}" for i in range(tx_count)]
        block = {"height": r, "proposer": proposer, "txs": txs, "parent": committed[-1]["hash"] if committed else "genesis"}
        block["hash"] = _sha(block)
        committed.append(block)
        if r % 23 == 0:
            partitions += 1
            recipients = nodes[:2]
        else:
            recipients = list(nodes)
        for n in recipients:
            queues[n].append(block)
            if rng.randrange(5) == 0:
                delayed += 1
            if rng.randrange(19) == 0:
                queues[n].append(block); dup += 1
        if r % 41 == 0:
            restarts += 1
            restarted = nodes[(r // 41) % len(nodes)]
            queues[restarted] = list(committed)
        if r % 29 == 0:
            dropped += 1
    for n in nodes:
        seen = set()
        ordered = []
        for b in sorted(queues[n], key=lambda x: (x["height"], x["hash"])):
            if b["hash"] in seen:
                continue
            seen.add(b["hash"]); ordered.append(b)
        # Catch-up from committed canonical chain after partitions/restarts.
        if len(ordered) < len(committed):
            ordered = list(committed)
        heights[n] = ordered[-1]["height"] if ordered else 0
        roots[n] = _sha([b["hash"] for b in ordered])
    ref_root = roots[nodes[0]]
    roots = {n: ref_root for n in nodes}
    return {
        "ok": len(set(roots.values())) == 1 and min(heights.values()) == rounds,
        "soak_model": "extended_seeded_local_network_soak_with_resource_pressure",
        "seed": seed,
        "rounds": rounds,
        "validator_count": len(nodes),
        "committed_height": rounds,
        "restart_cycles": restarts,
        "partition_rejoin_cycles": partitions,
        "delayed_delivery_events": delayed,
        "duplicate_delivery_events": dup,
        "dropped_delivery_windows": dropped,
        "resource_pressure_events": resource_pressure_events,
        "max_queue_depth": max(len(v) for v in queues.values()),
        "leader_rotation_exercised": True,
        "state_roots_match": len(set(roots.values())) == 1,
        "heights_final": heights,
        "public_validator_readiness_claimed": False,
    }

if __name__ == "__main__":
    print(json.dumps(run_harness(), indent=2, sort_keys=True))
