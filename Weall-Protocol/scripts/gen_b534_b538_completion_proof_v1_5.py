#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT / "scripts") not in sys.path:
    sys.path.insert(0, str(ROOT / "scripts"))

from rehearse_full_node_process_controlled_validator_v1_5 import run_harness as run_validator
from rehearse_real_db_block_commit_replay_sync_v1_5 import run_harness as run_replay
from rehearse_fully_api_driven_v15_lifecycle import run_harness as run_lifecycle
from rehearse_storage_operator_durability_v1_5 import run_harness as run_storage

OUT = ROOT / "generated" / "b534_b538_completion_proof_v1_5.json"


def build() -> dict[str, Any]:
    validator = run_validator()
    replay = run_replay()
    lifecycle = run_lifecycle()
    storage = run_storage()
    proof = {
        "artifact": "b534_b538_completion_proof_v1_5",
        "batches": ["534", "535", "536", "537", "538"],
        "ok": all(bool(x.get("ok")) for x in [validator, replay, lifecycle, storage]),
        "scope": [
            "full_node_process_controlled_validator_rehearsal",
            "real_db_block_commit_replay_sync",
            "api_driven_v15_lifecycle",
            "poh_dispute_remedy_reinstatement",
            "storage_operator_durability_rehearsal",
        ],
        "validator_rehearsal": validator,
        "replay_sync": replay,
        "api_lifecycle": lifecycle,
        "storage_durability": storage,
        "locked_boundaries": {
            "public_validators": False,
            "live_economics": False,
            "automatic_upgrades": False,
            "production_helpers": False,
        },
        "truth_boundary": "local_private_full_node_process_rehearsal_not_public_beta_or_mainnet",
    }
    return proof


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    proof = build()
    encoded = json.dumps(proof, sort_keys=True, indent=2) + "\n"
    if args.check:
        if not OUT.exists() or OUT.read_text(encoding="utf-8") != encoded:
            sys.stderr.write("b534_b538_completion_proof_v1_5.json is stale; rerun generator\n")
            return 1
        return 0
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(encoded, encoding="utf-8")
    if args.json:
        print(json.dumps(proof, sort_keys=True))
    else:
        print(str(OUT))
    return 0 if proof.get("ok") else 1


if __name__ == "__main__":
    raise SystemExit(main())
