#!/usr/bin/env python3
from __future__ import annotations

"""Generate/check observer-to-validator launch flow evidence."""

import argparse
import json
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "generated" / "observer_to_validator_launch_flow_v1_5.json"


def _pretty(obj: Any) -> str:
    return json.dumps(obj, indent=2, sort_keys=True, ensure_ascii=False) + "\n"


def build() -> dict[str, Any]:
    flow = [
        {
            "actor": "fresh_observer",
            "current_role": "none/local clone",
            "action": "boot public observer from checked-in signed registry",
            "route_or_tx": "scripts/boot_public_observer_testnet.sh; /v1/nodes/seeds; /v1/net/self",
            "protocol_gate": "registry signature, pinned signer, chain/network/genesis/profile/tx-index commitments",
            "state_transition": "local observer node starts; no validator signing",
            "frontend_surface": "public observer dashboard / node dashboard",
            "failure_code": "OBSERVER_BOOT_NO_VALID_REGISTRY_SOURCE or OBSERVER_BOOT_NO_DIRECT_P2P_SEED",
            "tests": [
                "tests/prod/test_public_observer_checked_in_registry_primary.py",
                "tests/prod/test_clean_observer_boot_from_checked_in_registry.py",
            ],
        },
        {
            "actor": "observer",
            "current_role": "observer",
            "action": "create account / submit allowed onboarding transaction upstream",
            "route_or_tx": "/v1/tx/submit via verified seed upstream",
            "protocol_gate": "transaction admission, chain id, signature, account/key custody rules",
            "state_transition": "account exists if tx is admitted and finalized under current phase",
            "frontend_surface": "profile/account page and tx status",
            "failure_code": "tx admission/apply failure code from failure_code_registry_v1_5",
            "tests": ["tests/prod/test_public_observer_seed_discovery.py"],
        },
        {
            "actor": "observer",
            "current_role": "account holder",
            "action": "complete PoH / Tier 2 eligibility path",
            "route_or_tx": "PoH bootstrap and Tier 2 eligibility transactions/routes",
            "protocol_gate": "PoH status and Tier 2 protocol predicates",
            "state_transition": "account becomes Tier 2 eligible when protocol state allows",
            "frontend_surface": "PoH page and readiness/review surfaces",
            "failure_code": "VALIDATOR_PROMOTION_POH_REQUIRED or VALIDATOR_PROMOTION_TIER2_REQUIRED",
            "tests": ["tests/test_observer_to_validator_authority_path.py"],
        },
        {
            "actor": "validator_candidate",
            "current_role": "Tier 2 account holder",
            "action": "opt into node/operator and validation responsibilities",
            "route_or_tx": "responsibility opt-in tx/API paths",
            "protocol_gate": "voluntary responsibility opt-in and readiness evidence",
            "state_transition": "candidate readiness recorded; not manually activated",
            "frontend_surface": "validator/operator page and node dashboard",
            "failure_code": "VALIDATOR_PROMOTION_OPERATOR_OPT_IN_REQUIRED or VALIDATOR_PROMOTION_VALIDATION_OPT_IN_REQUIRED",
            "tests": ["tests/prod/test_observer_cannot_enable_validator_signing.py"],
        },
        {
            "actor": "protocol_state",
            "current_role": "eligible validator candidates",
            "action": "activate validator set only at deterministic boundary",
            "route_or_tx": "validator-set update / epoch-open boundary",
            "protocol_gate": "consensus threshold, validator readiness, one-node-per-user and revocation rules",
            "state_transition": "active validator set updates deterministically when allowed",
            "frontend_surface": "validators page and readiness review",
            "failure_code": "VALIDATOR_PROMOTION_THRESHOLD_NOT_MET or VALIDATOR_PROMOTION_PROTOCOL_STATE_BLOCKED",
            "tests": [
                "tests/test_validator_set_activation_boundary.py",
                "tests/test_validator_lifecycle_multinode.py",
                "tests/prod/test_promoted_validator_live_rehearsal.py",
            ],
        },
    ]
    return {
        "schema": "weall.v1_5.observer_to_validator_launch_flow",
        "version": "2026-06-public-genesis-launch",
        "maintainer_manual_activation_authority": False,
        "observer_validator_signing_enabled_by_boot_script": False,
        "production_economics_active": False,
        "flow": flow,
        "source_files": [
            "scripts/boot_public_observer_testnet.sh",
            "src/weall/runtime/apply/roles.py",
            "src/weall/runtime/bft_hotstuff.py",
            "src/weall/api/routes_nodes.py",
            "tests/test_validator_set_activation_boundary.py",
        ],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate/check observer-to-validator launch flow artifact.")
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
            raise SystemExit(f"stale generated observer-to-validator flow: {OUT.relative_to(ROOT)}")
        print(f"OK: {OUT.relative_to(ROOT)} is current")
        return 0
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(text, encoding="utf-8")
    print(f"wrote {OUT.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
