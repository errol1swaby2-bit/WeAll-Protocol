#!/usr/bin/env python3
"""Deterministic legacy role/reviewer applier parity probe for pinned code revisions.

Run this same source file in two isolated Python environments (one with the
pinned base checkout installed, one with the candidate checkout installed).
It compares synthetic bounded-rollback applier behavior, not retained blocks,
transaction signature admission, policy v2, or independent consensus.
"""

from __future__ import annotations

import argparse
import copy
import json
from pathlib import Path
from typing import Any

import weall.runtime.apply.roles as role_module
from weall.runtime.apply.roles import RolesApplyError, apply_roles
from weall.runtime.bounded_rollback import run_with_bounded_rollback
from weall.runtime.state_hash import compute_state_root
from weall.runtime.tx_admission import TxEnvelope

TX_AND_ROLE = (
    ("ROLE_JUROR_ENROLL", "juror"),
    ("ROLE_JUROR_ACTIVATE", "juror"),
    ("ROLE_JUROR_REINSTATE", "juror"),
    ("ROLE_VALIDATOR_ACTIVATE", "validator"),
    ("ROLE_NODE_OPERATOR_ACTIVATE", "node_operator"),
    ("ROLE_EMISSARY_SEAT", "emissary"),
    ("ROLE_GOV_EXECUTOR_SET", "gov_executor"),
    ("REVIEWER_LANE_OPT_IN", "juror"),
    ("REVIEWER_LANE_OPT_OUT", "juror"),
)
SYSTEM_TX_TYPES = {
    "ROLE_VALIDATOR_ACTIVATE",
    "ROLE_NODE_OPERATOR_ACTIVATE",
    "ROLE_EMISSARY_SEAT",
    "ROLE_GOV_EXECUTOR_SET",
}
CONDITIONS = (
    "baseline",
    "banned",
    "locked",
    "tier1",
    "revoked",
    "low_reputation",
    "missing_account",
)


def input_state(*, role: str, condition: str, explicit_v1: bool) -> dict[str, Any]:
    state: dict[str, Any] = {
        "height": 21,
        "accounts": {
            "@alice": {
                "nonce": 0,
                "poh_tier": 2,
                "banned": False,
                "locked": False,
                "reputation": "6",
                "reputation_milli": 6000,
            }
        },
        "roles": {
            "jurors": {
                "by_id": {
                    "@alice": {
                        "enrolled": True,
                        "active": True,
                        "responsibilities": {
                            "reviewer": {"dispute_review": {"active": True, "opted_in": True}}
                        },
                    }
                },
                "active_set": ["@alice"],
            },
            "node_operators": {
                "by_id": {"@alice": {"enrolled": True, "active": True}},
                "active_set": ["@alice"],
            },
        },
    }
    if explicit_v1:
        state["params"] = {"reputation_role_gate_version": 1}
    account = state["accounts"]["@alice"]
    if condition == "banned":
        account["banned"] = True
    elif condition == "locked":
        account["locked"] = True
    elif condition == "tier1":
        account["poh_tier"] = 1
    elif condition == "revoked":
        state["reputation"] = {"role_eligibility": {"@alice": {"roles": {role: False}}}}
    elif condition == "low_reputation":
        account["reputation"] = "1"
        account["reputation_milli"] = 1000
    elif condition == "missing_account":
        state["accounts"] = {}
    elif condition != "baseline":
        raise ValueError(f"unknown_condition:{condition}")
    return state


def probe_one(tx_type: str, role: str, condition: str, explicit_v1: bool) -> dict[str, Any]:
    state = input_state(role=role, condition=condition, explicit_v1=explicit_v1)
    before = copy.deepcopy(state)
    system = tx_type in SYSTEM_TX_TYPES
    payload: dict[str, Any] = {
        "account_id": "@alice",
        "reputation_required_milli": 5000,
    }
    if tx_type.startswith("REVIEWER_LANE_"):
        payload["reviewer_lanes"] = ["dispute_review"]
    env = TxEnvelope(
        tx_type=tx_type,
        signer="SYSTEM" if system else "@alice",
        nonce=24,
        payload=payload,
        sig="synthetic-no-authentication",
        parent="synthetic-system-parent" if system else None,
        system=system,
    )
    output: dict[str, Any] = {
        "tx_type": tx_type,
        "condition": condition,
        "version": 1 if explicit_v1 else "absent",
    }
    try:
        metadata, _ = run_with_bounded_rollback(state, lambda ledger: apply_roles(ledger, env))
        output["status"] = "accepted"
        output["metadata"] = metadata
    except RolesApplyError as exc:
        output["status"] = "rejected"
        output["code"] = exc.code
        output["reason"] = exc.reason
        output["details"] = exc.details
        if state != before:
            raise AssertionError(f"failed_rollback:{tx_type}:{condition}:{explicit_v1}")
    output["state_root"] = compute_state_root(state)
    output["input_state_root"] = compute_state_root(before)
    return output


def collect() -> list[dict[str, Any]]:
    return [
        probe_one(tx_type, role, condition, version)
        for tx_type, role in TX_AND_ROLE
        for version in (False, True)
        for condition in CONDITIONS
    ]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--expected-package-root", type=Path, required=True)
    parser.add_argument("--report", type=Path, required=True)
    args = parser.parse_args()
    expected = (
        args.expected_package_root.resolve() / "src" / "weall" / "runtime" / "apply" / "roles.py"
    )
    if Path(role_module.__file__).resolve() != expected:
        raise SystemExit("wrong_installed_checkout:role_module_not_from_expected_revision")
    if args.report.exists() or not args.report.parent.is_dir():
        raise SystemExit("report_destination_invalid_or_already_exists")
    rows = collect()
    expected_rows = len(TX_AND_ROLE) * len(CONDITIONS) * 2
    if len(rows) != expected_rows:
        raise SystemExit("unexpected_case_count")
    # Capture the observable outcomes. No claim is made for undeclared
    # possible states, cryptographic signatures or historical policy epochs.
    report = {
        "schema": "weall.pr77.synthetic_legacy_role_parity.v1",
        "case_count": len(rows),
        "cases": rows,
        "real_retained_ledger_proven": False,
        "old_version_compatibility_proven": False,
        "independent_two_node_consensus_proven": False,
    }
    with args.report.open("x", encoding="utf-8") as stream:
        json.dump(report, stream, sort_keys=True, indent=2)
        stream.write("\n")
    print(f"synthetic_role_probe_cases={len(rows)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
