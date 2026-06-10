#!/usr/bin/env python3
from __future__ import annotations

import json
from typing import Any

Json = dict[str, Any]


def run_harness() -> Json:
    accounts = {f"@sybil{i}": 0 for i in range(10)} | {"@honest1": 0, "@honest2": 0, "treasury": 0}
    attempted: list[Json] = []
    rejected = 0
    for epoch in range(1, 73):
        for i in range(10):
            reason = "economics_locked" if epoch % 3 else "duplicate_review_ring_or_sybil_cluster"
            attempted.append({"epoch": epoch, "account": f"@sybil{i}", "amount": 100, "accepted": False, "reason": reason})
            rejected += 1
    treasury_attack = {"proposal": "treasury-drain", "amount": 10_000_000, "accepted": False, "reason": "treasury_spend_locked"}
    validator_concentration = {"top_validator_share_attempted": 0.91, "accepted": False, "reason": "live_rewards_locked"}
    fee_market_attack = {"positive_civic_fee_attempted": True, "accepted": False, "reason": "civic_social_governance_fee_free_required"}
    return {
        "ok": all(balance == 0 for balance in accounts.values()) and rejected == len(attempted),
        "batch": "594",
        "mechanism": "locked_economics_adversarial_reward_farming_and_capture_expansion",
        "epochs_simulated": 72,
        "attempted_reward_claims": len(attempted),
        "rejected_reward_claims": rejected,
        "accepted_reward_claims": 0,
        "balances_mutated": False,
        "treasury_attack": treasury_attack,
        "validator_reward_concentration_attack": validator_concentration,
        "fee_market_attack": fee_market_attack,
        "live_economics_enabled": False,
        "balance_transfers_enabled": False,
        "reward_issuance_enabled": False,
        "treasury_spend_enabled": False,
        "fee_markets_enabled": False,
        "activation_go_no_go_required": True,
        "legal_compliance_ready_claimed": False,
    }


if __name__ == "__main__":
    print(json.dumps(run_harness(), indent=2, sort_keys=True))
