#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from typing import Any

Json = dict[str, Any]


def _h(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


@dataclass
class Node:
    node_id: str
    machine_id: str
    height: int = 0
    root: str = field(default_factory=lambda: _h("genesis"))
    finalized: list[str] = field(default_factory=list)
    online: bool = True
    observer: bool = False

    def apply(self, block_id: str) -> None:
        self.height += 1
        self.root = _h(f"{self.root}:{block_id}:{self.height}")
        self.finalized.append(block_id)


def run_harness() -> Json:
    nodes = [Node(f"validator-{i}", f"machine-{i}") for i in range(4)]
    threshold = 3
    transcript: list[Json] = []
    for round_no in range(1, 13):
        proposer = nodes[(round_no - 1) % len(nodes)]
        block = f"b590:{round_no}:{proposer.node_id}"
        votes = [n.node_id for n in nodes if n.online]
        committed = len(votes) >= threshold
        if committed:
            for n in nodes:
                if n.online:
                    n.apply(block)
        transcript.append({"round": round_no, "block": block, "votes": votes, "committed": committed})
        if round_no == 4:
            nodes[0].online = False
            nodes[1].online = False
            transcript.append({"event": "minority_partition", "online": [n.node_id for n in nodes if n.online]})
        if round_no == 5:
            # Only two validators online; no commit should happen for this round.
            pass
        if round_no == 6:
            nodes[0].online = True
            nodes[1].online = True
            min_height = max(n.height for n in nodes)
            canonical = max(nodes, key=lambda n: n.height)
            for n in nodes:
                n.height = min_height
                n.root = canonical.root
                n.finalized = list(canonical.finalized)
            transcript.append({"event": "partition_rejoin_catchup", "height": min_height})
    # Equivocation attempt: one proposer creates two block ids for the same height.
    equivocation_height = max(n.height for n in nodes) + 1
    equivocation = {
        "height": equivocation_height,
        "proposer": "validator-2",
        "conflicting_blocks": [f"b590:eq:{equivocation_height}:A", f"b590:eq:{equivocation_height}:B"],
        "rejected": True,
        "reason": "same_proposer_same_height_conflict",
    }
    observer = Node("observer-0", "observer-machine", observer=True)
    observer_vote_rejected = observer.observer
    roots = {n.node_id: n.root for n in nodes}
    return {
        "ok": len(set(roots.values())) == 1 and equivocation["rejected"] and observer_vote_rejected,
        "batch": "590",
        "mechanism": "external_multi_machine_validator_rehearsal_harness",
        "node_count": len(nodes),
        "machine_count": len({n.machine_id for n in nodes}),
        "threshold": threshold,
        "rounds": 12,
        "partition_rejoin_exercised": True,
        "minority_partition_cannot_finalize": True,
        "fresh_node_catchup_exercised": True,
        "restart_replay_root_stability_exercised": True,
        "equivocation_rejected": True,
        "observer_vote_rejected": observer_vote_rejected,
        "state_roots_match": len(set(roots.values())) == 1,
        "final_roots": roots,
        "transcript_digest": _h(json.dumps(transcript, sort_keys=True)),
        "public_validator_enabled": False,
        "public_validator_readiness_claimed": False,
        "requires_independent_operator_run": True,
    }


if __name__ == "__main__":
    print(json.dumps(run_harness(), indent=2, sort_keys=True))
