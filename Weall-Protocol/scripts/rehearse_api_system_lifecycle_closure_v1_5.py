#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from typing import Any

from rehearse_public_api_write_lifecycle_v1_5 import run_harness as run_public_api_lifecycle

SYSTEM_DOMAIN_CLASSIFICATIONS: dict[str, dict[str, Any]] = {
    "poh_challenge": {
        "classification": "consensus_tx_direct_apply_in_lifecycle_harness",
        "public_api_status": "tx_submit_or_domain_route_required_before_external_client_claim",
        "public_client_required": True,
        "reason": "challenge open/resolve are user/system governance actions and should be covered by a public tx/API path before final external-client rehearsal",
    },
    "dispute_final_receipt": {
        "classification": "system_scheduled_receipt_only",
        "public_api_status": "not_public_write_expected",
        "public_client_required": False,
        "reason": "final receipts are emitted by system scheduling after dispute resolution/appeal, not accepted as public user writes",
    },
    "storage_receipt": {
        "classification": "operator_or_system_receipt",
        "public_api_status": "operator_worker_or_system_receipt_path_expected",
        "public_client_required": False,
        "reason": "storage pin confirmation is a node/operator receipt path and should not be exposed as a generic public user write",
    },
    "protocol_upgrade_record": {
        "classification": "governance_record_only_system_boundary",
        "public_api_status": "governance_system_record_not_auto_apply",
        "public_client_required": False,
        "reason": "protocol upgrade records remain governance/system metadata only; no automatic artifact application is permitted",
    },
}


def run_harness() -> dict[str, Any]:
    base = run_public_api_lifecycle()
    remaining = list(base.get("direct_apply_write_domains_remaining") or [])
    classified: dict[str, Any] = {}
    unclassified: list[str] = []
    public_client_gaps: list[str] = []
    for domain in remaining:
        key = str(domain)
        rec = SYSTEM_DOMAIN_CLASSIFICATIONS.get(key)
        if rec is None:
            unclassified.append(key)
            continue
        classified[key] = dict(rec)
        if bool(rec.get("public_client_required")):
            public_client_gaps.append(key)
    return {
        "ok": bool(base.get("ok")) and not unclassified,
        "batch": "545",
        "base_public_api_lifecycle_ok": bool(base.get("ok")),
        "api_write_routes_exercised": list(base.get("api_write_routes_exercised") or []),
        "api_read_routes_exercised": list(base.get("api_read_routes_exercised") or []),
        "remaining_direct_apply_domains": remaining,
        "classified_remaining_domains": classified,
        "unclassified_remaining_domains": unclassified,
        "public_client_write_gaps_remaining": public_client_gaps,
        "system_only_domains_not_public_writes": [k for k, v in classified.items() if not bool(v.get("public_client_required"))],
        "protocol_upgrade_record_only": bool(base.get("protocol_upgrade_record_only")),
        "live_economics_enabled": False,
        "public_validator_enabled": False,
    }


def main() -> int:
    ap = argparse.ArgumentParser(); ap.add_argument("--json", action="store_true"); args = ap.parse_args()
    out = run_harness()
    print(json.dumps(out, sort_keys=True, indent=2 if args.json else None))
    return 0 if out.get("ok") else 1


if __name__ == "__main__":
    raise SystemExit(main())
