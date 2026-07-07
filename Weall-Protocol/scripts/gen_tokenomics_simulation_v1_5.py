#!/usr/bin/env python3
from __future__ import annotations

"""Generate a locked-economics v1.5 tokenomics simulation artifact."""

import argparse
import json
from pathlib import Path
from typing import Any

from weall.ledger.constants import (
    HALVING_INTERVAL_ISSUANCE_EPOCHS,
    INITIAL_ISSUANCE_PER_EPOCH,
    ISSUANCE_EPOCH_BLOCKS,
    MAX_SUPPLY,
)
from weall.ledger.issuance import (
    cap_issuance_by_remaining_supply,
    epoch_issuance_subsidy_atomic,
    issuance_height_for_epoch,
)

REPO_ROOT = Path(__file__).resolve().parents[1]
OUT_PATH = REPO_ROOT / "generated" / "tokenomics_simulation_v1_5.json"
Json = dict[str, Any]


def _supply_schedule(sample_epochs: int) -> tuple[list[Json], int]:
    epochs = []
    issued = 0
    sample_epochs = max(1, int(sample_epochs))
    for epoch in range(sample_epochs):
        raw = epoch_issuance_subsidy_atomic(epoch)
        amount, remaining = cap_issuance_by_remaining_supply(issued, raw)
        issued += amount
        epochs.append(
            {
                "issuance_epoch": epoch,
                "due_height": issuance_height_for_epoch(epoch),
                "raw_subsidy_atomic": raw,
                "issued_atomic": amount,
                "total_issued_atomic": issued,
                "remaining_supply_atomic": remaining,
            }
        )
    return epochs, issued


def _halving_samples() -> list[Json]:
    out = []
    for window in range(6):
        epoch = int(window) * int(HALVING_INTERVAL_ISSUANCE_EPOCHS)
        out.append(
            {
                "issuance_epoch": epoch,
                "due_height": issuance_height_for_epoch(epoch),
                "subsidy_atomic": epoch_issuance_subsidy_atomic(epoch),
            }
        )
    return out


def _farming_scenarios() -> list[Json]:
    return [
        {
            "scenario_id": "sybil_review_farming_placeholder",
            "risk": "malicious users try to create many accounts or reviewer identities to farm future rewards",
            "current_live_reward_result": "blocked_economics_locked",
            "required_before_activation": [
                "one-human-one-account adversarial proof",
                "reviewer assignment manipulation tests",
                "reward concentration simulation using real reviewer distributions",
            ],
        },
        {
            "scenario_id": "validator_reward_concentration_placeholder",
            "risk": "small validator set captures issuance when validator rewards activate",
            "current_live_reward_result": "blocked_public_validator_and_economics_locked",
            "required_before_activation": [
                "public validator proof harness evidence",
                "stake/identity neutrality review",
                "reward share cap or transparent distribution proof if introduced later",
            ],
        },
        {
            "scenario_id": "treasury_spend_capture_placeholder",
            "risk": "governance capture attempts to route treasury funds before public readiness",
            "current_live_reward_result": "blocked_treasury_spend_locked",
            "required_before_activation": [
                "governance capture simulation",
                "deliberation/vote/finalization bypass tests",
                "public legal/compliance review",
            ],
        },
    ]


def build_payload(sample_epochs: int = 24) -> Json:
    epochs, issued = _supply_schedule(sample_epochs)
    near_cap_amount, near_cap_remaining = cap_issuance_by_remaining_supply(
        int(MAX_SUPPLY) - int(INITIAL_ISSUANCE_PER_EPOCH) + 1,
        int(INITIAL_ISSUANCE_PER_EPOCH),
    )
    return {
        "schema": "weall.v1_5.tokenomics_simulation",
        "version": "2026-06-batch14-expanded",
        "truth_boundaries": {
            "live_economics_enabled": False,
            "balance_transfer_enabled": False,
            "reward_issuance_enabled": False,
            "treasury_spend_enabled": False,
        },
        "additional_truth_boundaries": {
            "fee_markets_enabled": False,
            "civic_social_governance_actions_fee_free_required": True,
        },
        "constants": {
            "issuance_epoch_blocks": int(ISSUANCE_EPOCH_BLOCKS),
            "initial_issuance_per_epoch_atomic": int(INITIAL_ISSUANCE_PER_EPOCH),
            "halving_interval_issuance_epochs": int(HALVING_INTERVAL_ISSUANCE_EPOCHS),
            "max_supply_atomic": int(MAX_SUPPLY),
            "target_block_interval_seconds": 20,
        },
        "sample_epochs": epochs,
        "sample_total_issued_atomic": issued,
        "halving_samples": _halving_samples(),
        "cap_sample": {
            "issued_before_atomic": int(MAX_SUPPLY) - int(INITIAL_ISSUANCE_PER_EPOCH) + 1,
            "raw_requested_atomic": int(INITIAL_ISSUANCE_PER_EPOCH),
            "issued_atomic": near_cap_amount,
            "remaining_after_atomic": near_cap_remaining,
        },
        "farming_and_capture_scenarios": _farming_scenarios(),
        "activation_blockade_checklist": [
            "economics_enabled remains false in public readiness phases",
            "balance transfers reject while economics is locked",
            "reward mint/distribute rejects while economics is locked",
            "treasury spend rejects while economics is locked",
            "positive fees for civic/social/governance actions are rejected",
            "launch matrix keeps live_economics, balance_transfer, reward_issuance, and treasury_spend disabled",
            "legal/compliance artifacts remain counsel-review-pending drafts",
            "public validator/BFT proof is complete before any validator reward claim",
        ],
    }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default=str(OUT_PATH))
    ap.add_argument("--sample-epochs", type=int, default=24)
    ap.add_argument("--check", action="store_true")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()
    out = Path(args.out)
    data = json.dumps(build_payload(args.sample_epochs), indent=2, sort_keys=True, ensure_ascii=False) + "\n"
    if args.json:
        print(data, end="")
        return 0
    if args.check:
        if not out.exists():
            raise SystemExit(f"missing generated tokenomics simulation: {out}")
        if out.read_text(encoding="utf-8") != data:
            raise SystemExit(f"stale generated tokenomics simulation: {out}")
        return 0
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(data, encoding="utf-8")
    print(str(out))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
