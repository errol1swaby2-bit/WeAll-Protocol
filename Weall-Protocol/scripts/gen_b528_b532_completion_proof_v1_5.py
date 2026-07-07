#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from rehearse_api_driven_full_lifecycle_v1_5 import run_harness as run_api_lifecycle
from rehearse_db_backed_fresh_node_replay_sync_v1_5 import run_harness as run_db_replay
from rehearse_live_node_process_validator_network_v1_5 import run_harness as run_live_validator

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "generated" / "b528_b532_completion_proof_v1_5.json"


def build() -> dict[str, Any]:
    validator = run_live_validator()
    replay = run_db_replay()
    lifecycle = run_api_lifecycle()
    feed = lifecycle.get("feed_ranking", {}) if isinstance(lifecycle, dict) else {}
    locked = {
        "public_validators": False,
        "live_economics": False,
        "automatic_upgrades": False,
        "production_helpers": False,
    }
    return {
        "ok": bool(validator.get("ok") and replay.get("ok") and lifecycle.get("ok") and not any(locked.values())),
        "artifact": "b528_b532_completion_proof_v1_5",
        "batches": [528, 529, 530, 531, 532],
        "scope": [
            "tcp_process_validator_rehearsal",
            "sqlite_db_backed_fresh_node_replay_sync",
            "api_driven_full_lifecycle",
            "poh_dispute_accountability_completion",
            "economics_storage_activation_complete_locked",
            "production_social_feed_ranking",
        ],
        "locked_boundaries": locked,
        "validator_rehearsal": validator,
        "fresh_node_replay_sync": replay,
        "api_lifecycle": lifecycle,
        "feed_ranking": {
            "mode": feed.get("mode"),
            "complete_for_deterministic_public_social_ranking": bool(feed.get("production_social_feed") and feed.get("uses_reputation_weighting") and feed.get("uses_anti_brigading_caps")),
            "complete_for_personalized_recommendation": False,
            "personalized": False,
            "uses_reputation_weighting": bool(feed.get("uses_reputation_weighting")),
            "uses_anti_brigading_caps": bool(feed.get("uses_anti_brigading_caps")),
            "uses_author_diversity_dampening": bool(feed.get("uses_author_diversity_dampening")),
            "cursor_model": feed.get("cursor_model"),
        },
        "truth_boundary": "local_private_completion_rehearsal_not_public_beta_or_mainnet",
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    data = build()
    text = json.dumps(data, sort_keys=True, indent=2) + "\n"
    if args.check:
        current = OUT.read_text(encoding="utf-8") if OUT.exists() else ""
        if current != text:
            raise SystemExit(f"stale generated artifact: {OUT.relative_to(ROOT)}\nrun: python3 scripts/gen_b528_b532_completion_proof_v1_5.py")
    else:
        OUT.parent.mkdir(parents=True, exist_ok=True)
        OUT.write_text(text, encoding="utf-8")
    if args.json:
        print(json.dumps(data, sort_keys=True))
    else:
        print(OUT)
    return 0 if data.get("ok") else 1


if __name__ == "__main__":
    raise SystemExit(main())
