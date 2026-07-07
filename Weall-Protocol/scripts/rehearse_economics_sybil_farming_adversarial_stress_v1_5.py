#!/usr/bin/env python3
from __future__ import annotations

import json
from typing import Any

from weall.runtime.apply.economics import economics_locked_sybil_farming_adversarial_summary, economics_locked_read_models, record_treasury_report

Json = dict[str, Any]


def run_harness() -> Json:
    state: Json = {"height": 1234, "params": {"economics_enabled": False}, "economics": {}}
    stress = economics_locked_sybil_farming_adversarial_summary(
        state,
        epochs=48,
        honest_accounts=["alice", "bob", "carol", "dave"],
        sybil_accounts=["sybil-a", "sybil-b", "sybil-c", "sybil-d", "sybil-e", "sybil-f"],
        max_claims_per_epoch=2,
    )
    treasury = record_treasury_report(
        state,
        report_id="treasury:stress:48",
        period="epochs:1-48",
        opening_balance=21_000_000,
        closing_balance=21_000_000,
        spends=[],
    )
    read = economics_locked_read_models(state)
    return {
        "ok": stress["economics_enabled"] is False and stress["rejected_claim_count"] > stress["accepted_claim_count"] and stress["sybil_recipient_rejections"] > 0 and treasury["public_accountability_report"] is True,
        "stress_summary": stress,
        "treasury_report": treasury,
        "read_model": read,
        "live_economics_claimed": False,
        "legal_compliance_review_boundary": "required_before_activation",
    }

if __name__ == "__main__":
    print(json.dumps(run_harness(), indent=2, sort_keys=True))
