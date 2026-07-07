#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from weall.runtime.bft_hotstuff import canonical_vote_message, quorum_threshold, validator_set_hash
from weall.runtime.proposer_selection import select_proposer

Json = dict[str, Any]
VALIDATORS = ("validator-a", "validator-b", "validator-c", "validator-d")
CHAIN_ID = "weall-v15-b505-adversarial-proof"
VIEW = 11
PARENT_ID = "block-parent-0010"


def _vote_hash(*, signer: str, block_id: str) -> str:
    block_hash = hashlib.sha256(f"{CHAIN_ID}|{VIEW}|{block_id}".encode()).hexdigest()
    msg = canonical_vote_message(
        chain_id=CHAIN_ID,
        view=VIEW,
        block_id=block_id,
        block_hash=block_hash,
        parent_id=PARENT_ID,
        signer=signer,
    )
    return hashlib.sha256(msg).hexdigest()


def _detect_equivocation(votes: list[Json]) -> list[Json]:
    seen: dict[tuple[str, int], str] = {}
    equivocations: list[Json] = []
    for v in votes:
        key = (str(v["signer"]), int(v["view"]))
        block_id = str(v["block_id"])
        prior = seen.get(key)
        if prior is not None and prior != block_id:
            equivocations.append({"signer": key[0], "view": key[1], "first_block_id": prior, "second_block_id": block_id})
        else:
            seen[key] = block_id
    return equivocations


def run_harness() -> Json:
    threshold = quorum_threshold(len(VALIDATORS))
    leader = select_proposer(active_set=list(VALIDATORS), chain_id=CHAIN_ID, height=VIEW)
    set_hash = validator_set_hash(list(VALIDATORS))

    honest_votes = [
        {"signer": v, "view": VIEW, "block_id": "block-canonical-0011", "vote_hash": _vote_hash(signer=v, block_id="block-canonical-0011")}
        for v in VALIDATORS
    ]
    partition_a = honest_votes[:2]
    partition_b = honest_votes[2:]
    partition_a_can_finalize = len(partition_a) >= threshold
    partition_b_can_finalize = len(partition_b) >= threshold

    equivocation_votes = [
        {"signer": "validator-a", "view": VIEW, "block_id": "block-left", "vote_hash": _vote_hash(signer="validator-a", block_id="block-left")},
        {"signer": "validator-a", "view": VIEW, "block_id": "block-right", "vote_hash": _vote_hash(signer="validator-a", block_id="block-right")},
    ]
    equivocations = _detect_equivocation(equivocation_votes)

    restart_rows = []
    for attempt in range(3):
        restart_rows.append({
            "attempt": attempt,
            "validator_set_hash": validator_set_hash(list(VALIDATORS)),
            "leader": select_proposer(active_set=list(VALIDATORS), chain_id=CHAIN_ID, height=VIEW),
            "threshold": quorum_threshold(len(VALIDATORS)),
        })

    ok = (
        threshold == 3
        and len({r["validator_set_hash"] for r in restart_rows}) == 1
        and len({r["leader"] for r in restart_rows}) == 1
        and bool(equivocations)
        and partition_a_can_finalize is False
        and partition_b_can_finalize is False
    )
    return {
        "artifact": "b505_bft_adversarial_proof_v1_5",
        "public_validator_enabled": False,
        "validator_count": len(VALIDATORS),
        "validator_set_hash": set_hash,
        "leader": leader,
        "quorum_threshold": threshold,
        "equivocation_detected": bool(equivocations),
        "equivocations": equivocations,
        "partition": {
            "partition_a_votes": len(partition_a),
            "partition_b_votes": len(partition_b),
            "partition_a_can_finalize": partition_a_can_finalize,
            "partition_b_can_finalize": partition_b_can_finalize,
        },
        "restart_rows": restart_rows,
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
