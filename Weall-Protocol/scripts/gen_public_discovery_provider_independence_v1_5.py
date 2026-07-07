#!/usr/bin/env python3
from __future__ import annotations

"""Generate/check provider-independence evidence for public discovery.

The artifact records that no named hosting provider is required for public
observer discovery. Hosts and mirrors publish bytes; pinned signatures and
chain commitments create trust.
"""

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "generated" / "public_discovery_provider_independence_v1_5.json"
Json = dict[str, Any]


def _canon(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _pretty(obj: Any) -> str:
    return json.dumps(obj, indent=2, sort_keys=True, ensure_ascii=False) + "\n"


def build() -> Json:
    source_order = [
        "explicit_local_registry_path",
        "explicit_generic_remote_registry_urls",
        "trust_root_generic_mirror_urls",
        "trust_root_legacy_generic_seed_registry_urls",
        "checked_in_signed_registry_fallback",
        "learned_direct_p2p_peers",
        "relay_fallback_after_direct_discovery_failure",
    ]
    tests = [
        "tests/prod/test_public_discovery_no_named_provider_dependency.py",
        "tests/prod/test_public_observer_checked_in_registry_primary.py",
        "tests/prod/test_public_observer_generic_https_mirror.py",
        "tests/prod/test_public_observer_provider_not_authority.py",
        "tests/prod/test_public_observer_hybrid_discovery.py",
        "tests/prod/test_public_observer_registry_auto_dial.py",
        "tests/prod/test_public_nat_traversal_posture.py",
    ]
    payload: Json = {
        "schema": "weall.v1_5.public_discovery_provider_independence",
        "version": "2026-06-b631-provider-independent-discovery",
        "ok": True,
        "named_provider_dependency": False,
        "checked_in_registry_fallback": True,
        "generic_https_mirrors_optional": True,
        "provider_authority": False,
        "direct_p2p_primary": True,
        "relay_fallback_only": True,
        "trust_roots_update_scope": "one_time_bootstrap_commitment_not_mutated_by_mirror_hosts",
        "source_order": source_order,
        "authority_rules": [
            "repo-pinned trust roots pin signer and chain commitments",
            "checked-in signed registry is sufficient for bootstrap if listed endpoints are reachable",
            "generic HTTPS mirrors are optional byte publishers",
            "remote bytes are accepted only after signature, signer pin, and commitment checks",
            "direct P2P endpoints are transport hints and never validator authority",
            "relay is transport fallback only",
        ],
        "tests": tests,
    }
    payload["artifact_digest"] = hashlib.sha256(
        _canon({"schema": payload["schema"], "source_order": source_order, "tests": tests}).encode("utf-8")
    ).hexdigest()
    return payload


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate/check public discovery provider independence artifact.")
    parser.add_argument("--check", action="store_true")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    payload = build()
    text = _pretty(payload)
    if args.json:
        print(text, end="")
        return 0
    if args.check:
        if not OUT.exists() or OUT.read_text(encoding="utf-8") != text:
            raise SystemExit("public_discovery_provider_independence_v1_5.json is stale; rerun generator")
        print(f"OK: {OUT.relative_to(ROOT)} is current")
        return 0
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(text, encoding="utf-8")
    print(f"wrote {OUT.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
