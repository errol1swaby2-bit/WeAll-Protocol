#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path

from rehearse_real_validator_network_v1_5 import run_harness as run_validator_network
from rehearse_fresh_node_replay_sync_v1_5 import run_harness as run_replay_sync
from rehearse_v15_full_lifecycle import run_harness as run_lifecycle

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "generated" / "b517_b521_completion_proof_v1_5.json"


def build() -> dict:
    validator = run_validator_network()
    replay = run_replay_sync()
    lifecycle = run_lifecycle()
    feed_review = {"current_default": "created_at_nonce_desc", "complete_ranking": False, "new_optional_modes": ["recency", "engagement", "balanced"], "personalized_ranking": False, "notes": "Default feed remains deterministic recency for compatibility; optional ranking is deterministic and state-derived but not a full personalized/reputation feed."}
    return {"version": 1, "batch": "517-521", "ok": bool(validator.get("ok") and replay.get("ok") and lifecycle.get("ok")), "public_claim_allowed": "private_rehearsal_only", "validator_network": validator, "fresh_node_replay_sync": replay, "full_lifecycle": lifecycle, "feed_ranking_review": feed_review, "locked_boundaries_preserved": {"public_validators_disabled": True, "live_economics_disabled": True, "automatic_protocol_upgrades_disabled": True, "production_helpers_disabled": True}}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    data = build()
    text = json.dumps(data, indent=2, sort_keys=True) + "\n"
    if args.check:
        if not OUT.exists() or OUT.read_text(encoding="utf-8") != text:
            raise SystemExit("b517_b521_completion_proof_v1_5.json is stale; rerun generator")
    else:
        OUT.parent.mkdir(parents=True, exist_ok=True)
        OUT.write_text(text, encoding="utf-8")
        print(str(OUT))
    return 0 if data.get("ok") else 1


if __name__ == "__main__":
    raise SystemExit(main())
