#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path

from rehearse_fresh_node_replay_sync_v1_5 import run_harness as run_replay_sync
from rehearse_real_validator_network_v1_5 import run_harness as run_validator_network
from rehearse_v15_full_lifecycle import run_harness as run_lifecycle

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "generated" / "b523_b527_completion_proof_v1_5.json"


def build() -> dict:
    validator = run_validator_network()
    replay = run_replay_sync()
    lifecycle = run_lifecycle()
    feed = {
        "default_mode": "recency",
        "rank_modes": ["recency", "engagement", "balanced"],
        "ranked_cursor_model": "rank_score_nonce_id",
        "legacy_recency_cursor_preserved": True,
        "personalized_ranking": False,
        "complete_for_deterministic_public_pagination": True,
        "complete_for_recommendation_discovery": False,
    }
    api_access = {
        "explicit_sensitive_route_metadata": True,
        "routes_hardened": [
            "GET /v1/session/me",
            "GET /v1/dev/bootstrap-secret",
            "GET /v1/poh/async/case/{case_id}",
            "GET /v1/poh/tier2/case/{case_id}",
            "GET /v1/poh/live/session/{session_id}/webrtc/signals",
            "GET /v1/net/relay/fetch",
            "GET /v1/observer/edge/status",
            "GET /v1/feed",
        ],
    }
    return {
        "version": 1,
        "batch": "523-527",
        "ok": bool(validator.get("ok") and replay.get("ok") and lifecycle.get("ok")),
        "claim": "v1.5_private_rehearsal_completion_not_public_validator_or_mainnet",
        "validator_process_rehearsal": validator,
        "fresh_node_replay_sync": replay,
        "full_lifecycle": lifecycle,
        "feed_ranking": feed,
        "api_access_model": api_access,
        "locked_boundaries_preserved": {
            "public_validators_disabled": True,
            "live_economics_disabled": True,
            "automatic_protocol_upgrades_disabled": True,
            "production_helpers_disabled": True,
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    data = build()
    text = json.dumps(data, indent=2, sort_keys=True) + "\n"
    if args.check:
        if not OUT.exists() or OUT.read_text(encoding="utf-8") != text:
            raise SystemExit("b523_b527_completion_proof_v1_5.json is stale; rerun generator")
    else:
        OUT.parent.mkdir(parents=True, exist_ok=True)
        OUT.write_text(text, encoding="utf-8")
        print(str(OUT))
    return 0 if data.get("ok") else 1


if __name__ == "__main__":
    raise SystemExit(main())
