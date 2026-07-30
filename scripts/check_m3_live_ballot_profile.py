#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import urllib.request
from pathlib import Path
from typing import Any

EXPECTED_PROFILE = "controlled-testnet-aggregate-v1"
EXPECTED_REASON = "active_controlled_testnet_profile"


def fetch_json(url: str) -> dict[str, Any]:
    request = urllib.request.Request(url, headers={"Accept": "application/json"})
    with urllib.request.urlopen(request, timeout=10) as response:
        value = json.loads(response.read().decode("utf-8"))
    if not isinstance(value, dict):
        raise SystemExit("m3_ballot_profile_response_not_object")
    return value


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--api-base", required=True)
    parser.add_argument("--out", required=True)
    parser.add_argument("--implementation-freeze", required=True)
    parser.add_argument("--implementation-tree", required=True)
    args = parser.parse_args()

    api_base = args.api_base.rstrip("/")
    payload = fetch_json(api_base + "/v1/gov/ballot-profile")
    profile = payload.get("ballot_profile")
    if not isinstance(profile, dict):
        raise SystemExit("m3_ballot_profile_missing")
    expected = {
        "profile_id": EXPECTED_PROFILE,
        "active": True,
        "strict": True,
        "mode": "controlled-testnet",
        "reason": EXPECTED_REASON,
    }
    actual = {key: profile.get(key) for key in expected}
    if actual != expected:
        raise SystemExit(
            "m3_ballot_profile_not_strict_active:" + json.dumps({"expected": expected, "actual": actual}, sort_keys=True)
        )

    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    result = {
        "schema_version": 1,
        "implementation_freeze_commit": args.implementation_freeze,
        "implementation_tree": args.implementation_tree,
        "api_base": api_base,
        "ok": True,
        "ballot_profile": actual,
    }
    out.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
