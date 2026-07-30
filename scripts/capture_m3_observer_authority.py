#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import urllib.request
from pathlib import Path
from typing import Any


def fetch(base: str, route: str) -> dict[str, Any]:
    with urllib.request.urlopen(base.rstrip("/") + route, timeout=15) as response:
        value = json.loads(response.read().decode("utf-8"))
    if not isinstance(value, dict):
        raise SystemExit(f"m3_observer_authority_non_object:{route}")
    return value


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--api-base", required=True)
    parser.add_argument("--out", required=True)
    parser.add_argument("--implementation-freeze", required=True)
    parser.add_argument("--implementation-tree", required=True)
    args = parser.parse_args()

    status = fetch(args.api_base, "/v1/status")
    readyz = fetch(args.api_base, "/v1/readyz")
    consensus = fetch(args.api_base, "/v1/status/consensus")

    mode = str(status.get("mode") or "").strip().lower()
    if mode != "observer":
        raise SystemExit(f"m3_observer_runtime_mode_invalid:{mode or '<missing>'}")

    node_lifecycle = consensus.get("node_lifecycle") if isinstance(consensus.get("node_lifecycle"), dict) else {}
    authority_contract = readyz.get("authority_contract") if isinstance(readyz.get("authority_contract"), dict) else {}
    checks = {
        "local_is_active_validator": consensus.get("local_is_active_validator") is False,
        "local_is_expected_leader": consensus.get("local_is_expected_leader") is False,
        "validator_active": consensus.get("validator_active") is False,
        "bft_enabled_effective": node_lifecycle.get("bft_enabled_effective") is False,
        "validator_signing_enabled": node_lifecycle.get("validator_signing_enabled") is False,
        "validator_effective": authority_contract.get("validator_effective") is False,
        "helper_effective": authority_contract.get("helper_effective") is False,
    }
    failed = sorted(name for name, ok in checks.items() if not ok)
    if failed:
        raise SystemExit(f"m3_observer_runtime_authority_present:{failed}")

    result = {
        "schema_version": 1,
        "implementation_freeze_commit": str(args.implementation_freeze),
        "implementation_tree": str(args.implementation_tree),
        "api_base": str(args.api_base).rstrip("/"),
        "mode": mode,
        "chain_id": str(status.get("chain_id") or ""),
        "height": int(status.get("height") or 0),
        "node_id": str(status.get("node_id") or consensus.get("node_id") or "m3-observer-node"),
        "authority_checks": checks,
        "authority_absent": all(checks.values()),
        "truth_boundary": "Runtime observer status and authority surfaces only; no validator, BFT, helper, treasury, or governance authority is claimed.",
    }
    if not result["chain_id"]:
        raise SystemExit("m3_observer_runtime_chain_id_missing")
    out = Path(args.out).expanduser().resolve()
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(out)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
