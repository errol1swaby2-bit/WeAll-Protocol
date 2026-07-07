#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from typing import Any

from rehearse_public_style_validator_network_mechanics_v1_5 import run_harness as run_public_style_validator


def run_harness() -> dict[str, Any]:
    base = run_public_style_validator()
    follower_results = list(base.get("follower_apply_ok_results") or [])
    follower_errors = list(base.get("follower_apply_errors") or [])
    return {
        "ok": bool(base.get("ok") and follower_results and all(follower_results) and follower_errors == ["", "", ""]),
        "batch": "562",
        "source_batch": str(base.get("batch") or ""),
        "follower_apply_ok_results": follower_results,
        "follower_apply_errors": follower_errors,
        "follower_apply_all_ok": bool(base.get("follower_apply_all_ok")),
        "block_context_fields": base.get("follower_apply_block_context_fields"),
        "block_producer_surface_used": base.get("block_producer_surface_used"),
        "net_loop_class": base.get("net_loop_class"),
        "state_roots_match_after_restart": bool(base.get("state_roots_match_after_restart")),
        "public_validator_enabled": bool(base.get("public_validator_enabled")),
        "public_validator_readiness_claimed": False,
    }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()
    out = run_harness()
    print(json.dumps(out, sort_keys=True, indent=2 if args.json else None))
    return 0 if out.get("ok") else 1


if __name__ == "__main__":
    raise SystemExit(main())
