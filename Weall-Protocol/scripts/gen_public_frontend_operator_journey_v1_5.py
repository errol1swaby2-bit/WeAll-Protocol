#!/usr/bin/env python3
from __future__ import annotations

"""Generate/check the public-observer frontend operator journey evidence scaffold."""

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
REPO = ROOT.parent
OUT = ROOT / "generated" / "public_frontend_operator_journey_v1_5.json"
Json = dict[str, Any]


def _canon(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"))


def _pretty(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, indent=2) + "\n"


def _contains(rel: str, needle: str) -> bool:
    try:
        return needle in (REPO / rel).read_text(encoding="utf-8")
    except Exception:
        return False


def build() -> Json:
    source_checks = {
        "node_dashboard_public_seed_surface": _contains("web/src/pages/NodeDashboard.tsx", "Seed, validator, and tx propagation visibility"),
        "node_dashboard_validator_freshness_surface": _contains("web/src/pages/NodeDashboard.tsx", "Fresh validator endpoints"),
        "node_dashboard_nat_recovery_surface": _contains("web/src/pages/NodeDashboard.tsx", "Peer / NAT recovery"),
        "node_dashboard_promotion_path_surface": _contains("web/src/pages/NodeDashboard.tsx", "Validator promotion path"),
        "validator_wizard_backend_derived": _contains("web/src/components/ValidatorReadinessWizard.tsx", "Backend-derived"),
        "tx_lifecycle_component_present": _contains("web/src/components/TxPropagationTimeline.tsx", "Propagation lifecycle"),
        "tx_page_uses_lifecycle_component": _contains("web/src/pages/TransactionsPage.tsx", "TxPropagationTimeline"),
        "tx_lifecycle_upstream_acceptance_label": _contains("web/src/pages/TransactionsPage.tsx", "Upstream validator accepted"),
        "rendered_public_observer_spec_present": (REPO / "web" / "tests" / "e2e" / "public_observer_dashboard.spec.ts").is_file(),
        "package_script_public_observer_rendered_present": _contains("web/package.json", "test:public-observer-rendered"),
    }
    required_surfaces = [
        "seed registry signature status",
        "seed API and P2P counts",
        "active validators",
        "verified and fresh endpoint counts",
        "observer edge outbox/upstream/confirmed counts",
        "peer connectivity and NAT/relay recovery guidance",
        "backend-derived validator promotion checklist",
        "transaction propagation timeline including local, upstream, confirmed, and local-sync states",
    ]
    payload: Json = {
        "schema": "weall.v1_5.public_frontend_operator_journey",
        "version": "2026-06-b629-public-frontend-operator-journey",
        "ok": all(source_checks.values()),
        "public_observer_launch_ready": False,
        "rendered_e2e_available": source_checks["rendered_public_observer_spec_present"],
        "rendered_e2e_executed_by_this_artifact": False,
        "external_evidence_required_before_launch": True,
        "source_checks": source_checks,
        "required_surfaces": required_surfaces,
        "validation_command": "cd web && npm run test:public-observer-rendered",
        "claim_boundary": "This artifact proves source/rendered-test coverage is present; a launch claim still requires running the rendered test in the release environment.",
    }
    payload["artifact_digest"] = hashlib.sha256(_canon({"source_checks": source_checks, "required_surfaces": required_surfaces}).encode("utf-8")).hexdigest()
    return payload


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate/check public frontend operator journey evidence scaffold.")
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
            raise SystemExit("public_frontend_operator_journey_v1_5.json is stale; rerun generator")
        print(f"OK: {OUT.relative_to(ROOT)} is current ({len(payload['required_surfaces'])} surfaces)")
        return 0 if payload.get("ok") else 1
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(text, encoding="utf-8")
    print(f"wrote {OUT.relative_to(ROOT)} ({len(payload['required_surfaces'])} surfaces)")
    return 0 if payload.get("ok") else 1


if __name__ == "__main__":
    raise SystemExit(main())
