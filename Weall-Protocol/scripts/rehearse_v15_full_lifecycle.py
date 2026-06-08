#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json

from rehearse_real_validator_network_v1_5 import run_harness as run_validator_network
from rehearse_fresh_node_replay_sync_v1_5 import run_harness as run_replay_sync


def run_harness() -> dict:
    validator = run_validator_network()
    replay = run_replay_sync()
    locked_boundaries = {"public_validators": False, "live_economics": False, "automatic_upgrades": False, "production_helpers": False}
    return {"ok": bool(validator.get("ok") and replay.get("ok") and not any(locked_boundaries.values())), "batch": "521", "validator_network": validator, "fresh_node_replay_sync": replay, "locked_boundaries": locked_boundaries, "lifecycle_domains": ["account", "poh", "content", "feed", "dispute", "governance", "validator", "state_sync", "storage", "locked_economics"]}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    out = run_harness()
    print(json.dumps(out, sort_keys=True, indent=None if args.json else 2))
    return 0 if out.get("ok") else 1


if __name__ == "__main__":
    raise SystemExit(main())
