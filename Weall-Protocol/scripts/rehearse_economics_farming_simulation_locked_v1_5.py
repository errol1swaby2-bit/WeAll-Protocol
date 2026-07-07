#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from typing import Any

from rehearse_economics_activation_locked_completion_v1_5 import _complete_locked_state, _env
from weall.runtime.apply.economics import EconomicsApplyError, _activation_precondition_report, apply_economics


def _simulate_reward_claim(policy: dict[str, Any], seen: set[tuple[str, str, int]], *, account_id: str, work_id: str, epoch: int, active_poh: bool, locked: bool) -> dict[str, Any]:
    eligibility = policy.get("reward_policy", {}).get("recipient_eligibility", {}) if isinstance(policy.get("reward_policy"), dict) else {}
    anti = policy.get("anti_farming_policy", {}) if isinstance(policy.get("anti_farming_policy"), dict) else {}
    if eligibility.get("requires_active_poh") and not active_poh:
        return {"ok": False, "reason": "recipient_requires_active_poh"}
    if eligibility.get("no_locked_or_banned_accounts") and locked:
        return {"ok": False, "reason": "recipient_locked_or_banned"}
    if anti.get("requires_unique_work_id") and not work_id:
        return {"ok": False, "reason": "missing_work_id"}
    key = (account_id, work_id, int(epoch))
    if key in seen:
        return {"ok": False, "reason": "duplicate_work_id_epoch"}
    per_epoch_claims = len([x for x in seen if x[0] == account_id and x[2] == int(epoch)])
    if per_epoch_claims >= int(anti.get("max_reward_claims_per_epoch") or 0):
        return {"ok": False, "reason": "max_reward_claims_per_epoch_exceeded"}
    seen.add(key)
    return {"ok": True, "reason": "accepted"}


def run_harness() -> dict[str, Any]:
    state = _complete_locked_state()
    report = _activation_precondition_report(state)
    transfer_error = ""
    try:
        apply_economics(state, _env("BALANCE_TRANSFER", "@alice", 1, {"to_account_id": "@bob", "amount": 1, "transfer_id": "farm-transfer"}))
    except EconomicsApplyError as exc:
        transfer_error = exc.reason
    economics = state.get("economics", {}) if isinstance(state.get("economics"), dict) else {}
    seen: set[tuple[str, str, int]] = set()
    first = _simulate_reward_claim(economics, seen, account_id="@alice", work_id="work:1", epoch=7, active_poh=True, locked=False)
    duplicate = _simulate_reward_claim(economics, seen, account_id="@alice", work_id="work:1", epoch=7, active_poh=True, locked=False)
    second_same_epoch = _simulate_reward_claim(economics, seen, account_id="@alice", work_id="work:2", epoch=7, active_poh=True, locked=False)
    inactive = _simulate_reward_claim(economics, seen, account_id="@inactive", work_id="work:3", epoch=7, active_poh=False, locked=False)
    locked = _simulate_reward_claim(economics, seen, account_id="@locked", work_id="work:4", epoch=7, active_poh=True, locked=True)
    return {
        "ok": bool(report.get("ready") is True and transfer_error == "economics_disabled" and first.get("ok") is True and duplicate.get("reason") == "duplicate_work_id_epoch" and second_same_epoch.get("reason") == "max_reward_claims_per_epoch_exceeded" and inactive.get("reason") == "recipient_requires_active_poh" and locked.get("reason") == "recipient_locked_or_banned"),
        "batch": "566",
        "activation_preconditions_ready": bool(report.get("ready")),
        "live_economics_enabled": bool(state.get("params", {}).get("economics_enabled")),
        "transfer_before_activation_rejected_reason": transfer_error,
        "reward_farming_simulation_model": "deterministic_policy_pre_activation_simulation",
        "first_unique_claim": first,
        "duplicate_work_rejection": duplicate,
        "max_claims_rejection": second_same_epoch,
        "inactive_poh_rejection": inactive,
        "locked_account_rejection": locked,
        "long_run_simulation_claimed": False,
        "legal_compliance_claimed": False,
    }


def main() -> int:
    ap = argparse.ArgumentParser(); ap.add_argument("--json", action="store_true"); args = ap.parse_args()
    out = run_harness()
    print(json.dumps(out, sort_keys=True, indent=2 if args.json else None))
    return 0 if out.get("ok") else 1


if __name__ == "__main__":
    raise SystemExit(main())
