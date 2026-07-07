#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from weall.runtime.apply.economics import economics_locked_long_run_stress_summary, economics_locked_read_models, record_locked_transfer_attempt, record_locked_reward_claim, record_treasury_report


def run_harness() -> dict:
    state = {"height": 1200, "params": {"economics_enabled": False}, "economics": {}}
    stress = economics_locked_long_run_stress_summary(
        state,
        epochs=24,
        accounts=["alice", "bob", "carol", "locked-dave", "banned-erin"],
        max_claims_per_epoch=2,
    )
    pending = record_locked_transfer_attempt(state, transfer_id="tx-pending", from_account="alice", to_account="bob", amount=5, status="pending", reason="awaiting_activation")
    failed = record_locked_transfer_attempt(state, transfer_id="tx-failed", from_account="alice", to_account="carol", amount=50, status="failed", reason="economics_disabled")
    claim = record_locked_reward_claim(state, claim_id="reward-stress-1", account_id="alice", epoch=24, amount=1, status="pending", reason="locked_read_model")
    report = record_treasury_report(state, report_id="treasury-24", period="epochs-1-24", opening_balance=0, closing_balance=0, spends=[])
    read = economics_locked_read_models(state)
    ok = bool(not stress["economics_enabled"] and not stress["live_mutation_enabled"] and stress["rejected_claim_count"] > 0 and failed["status"] == "failed" and read["live_mutation_enabled"] is False)
    return {
        "ok": ok,
        "batch": "576",
        "stress_summary": stress,
        "pending_transfer_record": pending,
        "failed_transfer_record": failed,
        "reward_claim_record": claim,
        "treasury_report": report,
        "read_model": read,
        "long_run_epochs": stress["epochs"],
        "live_economics_claimed": False,
    }


def main() -> int:
    argparse.ArgumentParser().parse_args(); print(json.dumps(run_harness(), sort_keys=True, indent=2)); return 0

if __name__ == "__main__":
    raise SystemExit(main())
