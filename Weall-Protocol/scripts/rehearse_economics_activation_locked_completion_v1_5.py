#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from typing import Any

from weall.runtime.apply.economics import EconomicsApplyError, _activation_precondition_report, apply_economics
from weall.runtime.tx_admission import TxEnvelope


def _env(tx_type: str, signer: str, nonce: int, payload: dict[str, Any], *, system: bool = False, parent: str | None = None) -> TxEnvelope:
    return TxEnvelope(tx_type=tx_type, signer=signer, nonce=nonce, chain_id="batch560-economics", payload=payload, sig="sig", system=system, parent=parent)


def _complete_locked_state() -> dict[str, Any]:
    return {
        "height": 60,
        "time": 2_000_000_000,
        "params": {"economics_enabled": False, "economic_unlock_time": 1, "economics_strict_activation_preconditions_v2": True},
        "accounts": {"SYSTEM": {"balance": 0}, "@alice": {"balance": 100}, "@bob": {"balance": 0}},
        "tokenomics_simulation": {"cap": 21_000_000, "epoch_count": 8, "checksum": "sim-v1"},
        "treasury_wallets": {"public_goods": {"account_id": "treasury:public_goods", "balance": 0}},
        "economics": {
            "fee_policy": {"transfer_fee_int": 0, "post_fee_int": 0, "comment_fee_int": 0, "governance_vote_fee_int": 0},
            "wallet_policy": {"initialization": "explicit_account_register_or_genesis", "recovery": "manual_governance_or_user_key_rotation", "pending_failed_read_model": True},
            "reward_policy": {"eligible_roles": ["juror", "reviewer", "operator", "validator", "creator"], "recipient_eligibility": {"requires_active_poh": True, "no_locked_or_banned_accounts": True}},
            "anti_farming_policy": {"duplicate_reward_window_blocks": 1000, "max_reward_claims_per_epoch": 1, "requires_unique_work_id": True},
            "transfer_receipt_policy": {"pending_receipts": True, "failed_receipts": True, "dedupe_by_transfer_id": True},
            "treasury_accountability_policy": {"public_report_required": True, "spend_receipt_required": True, "governance_parent_required": True},
        },
    }


def run_harness() -> dict[str, Any]:
    missing_state: dict[str, Any] = {"height": 60, "time": 2_000_000_000, "params": {"economics_enabled": False, "economic_unlock_time": 1, "economics_strict_activation_preconditions_v2": True}, "accounts": {"SYSTEM": {}}}
    missing_error = ""
    try:
        apply_economics(missing_state, _env("ECONOMICS_ACTIVATION", "SYSTEM", 1, {"enable": True, "enforce_preconditions": True}, system=True, parent="gov"))
    except EconomicsApplyError as exc:
        missing_error = exc.reason
    ready_state = _complete_locked_state()
    report = _activation_precondition_report(ready_state)
    # Prove wallet transfer remains fail-closed before activation despite the
    # activation-complete policy set being present.
    transfer_error = ""
    try:
        apply_economics(ready_state, _env("BALANCE_TRANSFER", "@alice", 1, {"to_account_id": "@bob", "amount": 1, "transfer_id": "t-1"}))
    except EconomicsApplyError as exc:
        transfer_error = exc.reason
    return {
        "ok": bool(missing_error == "economics_activation_preconditions_not_satisfied" and report.get("ready") is True and transfer_error == "economics_disabled" and ready_state.get("params", {}).get("economics_enabled") is False),
        "batch": "560",
        "strict_preconditions_missing_error": missing_error,
        "activation_precondition_report": report,
        "wallet_initialization_policy_present": bool(report.get("checks", {}).get("wallet_initialization_policy_present")),
        "reward_recipient_eligibility_present": bool(report.get("checks", {}).get("reward_recipient_eligibility_present")),
        "anti_farming_policy_present": bool(report.get("checks", {}).get("anti_farming_policy_present")),
        "transfer_receipt_policy_present": bool(report.get("checks", {}).get("transfer_receipt_policy_present")),
        "treasury_accountability_policy_present": bool(report.get("checks", {}).get("treasury_accountability_policy_present")),
        "preconditions_ready_if_governance_chooses_activation": bool(report.get("ready")),
        "live_economics_enabled": bool(ready_state.get("params", {}).get("economics_enabled")),
        "transfer_before_activation_rejected_reason": transfer_error,
    }


def main() -> int:
    ap = argparse.ArgumentParser(); ap.add_argument("--json", action="store_true"); args = ap.parse_args()
    out = run_harness()
    print(json.dumps(out, sort_keys=True, indent=2 if args.json else None))
    return 0 if out.get("ok") else 1


if __name__ == "__main__":
    raise SystemExit(main())
