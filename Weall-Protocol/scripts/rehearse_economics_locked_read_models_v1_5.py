#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from typing import Any

from rehearse_economics_activation_locked_completion_v1_5 import _complete_locked_state, _env
from weall.runtime.apply.economics import EconomicsApplyError, apply_economics, economics_locked_read_models, record_locked_reward_claim, record_locked_transfer_attempt, record_treasury_report


def run_harness() -> dict[str, Any]:
    state = _complete_locked_state()
    state["height"] = 200
    pending = record_locked_transfer_attempt(state, transfer_id="tx-pending-1", from_account="@alice", to_account="@bob", amount=50, status="pending", reason="awaiting_activation")
    failed = record_locked_transfer_attempt(state, transfer_id="tx-failed-1", from_account="@alice", to_account="@mallory", amount=500, status="failed", reason="economics_disabled")
    reward_ok = record_locked_reward_claim(state, claim_id="reward-1", account_id="@alice", epoch=12, amount=7, status="eligible_pending_activation")
    reward_reject = record_locked_reward_claim(state, claim_id="reward-2", account_id="@locked", epoch=12, amount=7, status="failed", reason="recipient_locked_or_banned")
    treasury = record_treasury_report(state, report_id="treasury-q1", period="epoch-12", opening_balance=1000, closing_balance=950, spends=[{"spend_id": "spend-1", "amount": 50, "status": "approved_pending_activation"}])
    transfer_error = ""
    try:
        apply_economics(state, _env("BALANCE_TRANSFER", "@alice", 9, {"to_account_id": "@bob", "amount": 1, "transfer_id": "locked-live-transfer"}))
    except EconomicsApplyError as exc:
        transfer_error = exc.reason
    model = economics_locked_read_models(state)
    pending_model = model["pending_transfers"]
    failed_model = model["failed_transfers"]
    reward_ledger = model["reward_claim_ledger"]
    treasury_reports = model["treasury_reporting"]
    return {
        "ok": bool(model.get("economics_enabled") is False and transfer_error == "economics_disabled" and "tx-pending-1" in pending_model and "tx-failed-1" in failed_model and "reward-1" in reward_ledger.get("claims", {}) and "treasury-q1" in treasury_reports.get("reports", {})),
        "batch": "571",
        "economics_enabled": model.get("economics_enabled"),
        "live_mutation_enabled": model.get("live_mutation_enabled"),
        "transfer_before_activation_rejected_reason": transfer_error,
        "pending_transfer_record": pending,
        "failed_transfer_record": failed,
        "reward_claim_records": [reward_ok, reward_reject],
        "reward_claim_ledger_claim_count": len(reward_ledger.get("claims", {})),
        "reward_claim_ledger_epoch_12": reward_ledger.get("by_epoch", {}).get("12", []),
        "treasury_report": treasury,
        "treasury_report_count": len(treasury_reports.get("reports", {})),
        "legal_compliance_review_boundary": "required_before_activation",
        "live_economics_claimed": False,
    }


def main() -> int:
    ap = argparse.ArgumentParser(); ap.add_argument("--json", action="store_true"); args = ap.parse_args()
    out = run_harness()
    print(json.dumps(out, sort_keys=True, indent=2 if args.json else None))
    return 0 if out.get("ok") else 1


if __name__ == "__main__":
    raise SystemExit(main())
