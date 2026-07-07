#!/usr/bin/env python3
from __future__ import annotations

"""Generate/check the public validator endpoint churn proof scaffold."""

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "generated" / "public_validator_endpoint_churn_proof_v1_5.json"
Json = dict[str, Any]


def _canon(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"))


def _pretty(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, indent=2) + "\n"


def _contains(rel: str, needle: str) -> bool:
    try:
        return needle in (ROOT / rel).read_text(encoding="utf-8")
    except Exception:
        return False


def build() -> Json:
    source_checks = {
        "validators_route_exposes_fresh_endpoint_counts": _contains("src/weall/api/routes_nodes.py", "verified_fresh_endpoint_count"),
        "validators_route_exposes_stale_endpoint_counts": _contains("src/weall/api/routes_nodes.py", "stale_verified_endpoint_count"),
        "validators_route_preserves_protocol_state_authority_boundary": _contains("src/weall/api/routes_nodes.py", "endpoint_advertisement_grants_validator_status"),
        "auto_dial_uses_verified_registry_peer_uris": _contains("src/weall/net/net_loop.py", "verified_peer_uris_from_registry"),
        "unsigned_endpoint_regression_test_present": _contains("tests/prod/test_public_observer_registry_auto_dial.py", "not in peers") and _contains("tests/prod/test_public_observer_registry_auto_dial.py", "30305"),
        "endpoint_freshness_dashboard_surface_present": _contains("../web/src/pages/NodeDashboard.tsx", "Fresh validator endpoints"),
    }
    scenarios = [
        {
            "id": "active_validator_without_endpoint_warns",
            "required_before_public_observer_launch": True,
            "expected_behavior": "validator is visible from protocol state but all_active_validators_have_verified_fresh_endpoint=false",
        },
        {
            "id": "stale_signed_endpoint_warns",
            "required_before_public_observer_launch": True,
            "expected_behavior": "verified endpoint remains a hint but freshness.reason=stale and dashboard warns",
        },
        {
            "id": "fresh_signed_endpoint_clears_warning",
            "required_before_public_observer_launch": True,
            "expected_behavior": "verified_fresh_endpoint_count increments and active validator becomes reachable",
        },
        {
            "id": "unsigned_endpoint_never_auto_dials",
            "required_before_public_observer_launch": True,
            "expected_behavior": "endpoint hint may be displayed as unverified but is not a trusted P2P target",
        },
    ]
    payload: Json = {
        "schema": "weall.v1_5.public_validator_endpoint_churn_proof",
        "version": "2026-06-b629-validator-endpoint-churn-proof",
        "ok": all(source_checks.values()),
        "public_observer_launch_ready": False,
        "runtime_churn_transcript_attached": False,
        "external_evidence_required_before_launch": True,
        "purpose": "tracked proof scaffold for validator endpoint churn and freshness visibility",
        "source_checks": source_checks,
        "required_scenarios": scenarios,
        "runtime_command": "PYTHONPATH=src:scripts python scripts/run_public_observer_launch_rehearsal_v1_5.sh --api-base <seed-api> --registry configs/public_testnet_seed_registry.json --out generated/public_validator_endpoint_churn_runtime_transcript_v1_5.json",
        "claim_boundary": "Endpoint advertisements never grant validator authority; active validator status must come from protocol state.",
    }
    payload["artifact_digest"] = hashlib.sha256(_canon({"source_checks": source_checks, "scenarios": scenarios}).encode("utf-8")).hexdigest()
    return payload


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate/check public validator endpoint churn proof scaffold.")
    parser.add_argument("--check", action="store_true")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    payload = build()
    text = _pretty(payload)
    if args.json:
        print(text, end="")
        return 0 if payload.get("ok") else 1
    if args.check:
        if not OUT.exists() or OUT.read_text(encoding="utf-8") != text:
            raise SystemExit("public_validator_endpoint_churn_proof_v1_5.json is stale; rerun generator")
        print(f"OK: {OUT.relative_to(ROOT)} is current ({len(payload['required_scenarios'])} scenarios)")
        return 0 if payload.get("ok") else 1
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(text, encoding="utf-8")
    print(f"wrote {OUT.relative_to(ROOT)} ({len(payload['required_scenarios'])} scenarios)")
    return 0 if payload.get("ok") else 1


if __name__ == "__main__":
    raise SystemExit(main())
