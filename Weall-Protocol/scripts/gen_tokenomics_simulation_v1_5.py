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


def build_payload(sample_epochs: int = 12) -> Json:
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
    halving_samples = []
    for window in range(4):
        epoch = int(window) * int(HALVING_INTERVAL_ISSUANCE_EPOCHS)
        halving_samples.append(
            {
                "issuance_epoch": epoch,
                "due_height": issuance_height_for_epoch(epoch),
                "subsidy_atomic": epoch_issuance_subsidy_atomic(epoch),
            }
        )
    near_cap_amount, near_cap_remaining = cap_issuance_by_remaining_supply(
        int(MAX_SUPPLY) - int(INITIAL_ISSUANCE_PER_EPOCH) + 1,
        int(INITIAL_ISSUANCE_PER_EPOCH),
    )
    return {
        "schema": "weall.v1_5.tokenomics_simulation",
        "truth_boundaries": {
            "live_economics_enabled": False,
            "balance_transfer_enabled": False,
            "reward_issuance_enabled": False,
            "treasury_spend_enabled": False,
        },
        "constants": {
            "issuance_epoch_blocks": int(ISSUANCE_EPOCH_BLOCKS),
            "initial_issuance_per_epoch_atomic": int(INITIAL_ISSUANCE_PER_EPOCH),
            "halving_interval_issuance_epochs": int(HALVING_INTERVAL_ISSUANCE_EPOCHS),
            "max_supply_atomic": int(MAX_SUPPLY),
        },
        "sample_epochs": epochs,
        "halving_samples": halving_samples,
        "cap_sample": {
            "issued_before_atomic": int(MAX_SUPPLY) - int(INITIAL_ISSUANCE_PER_EPOCH) + 1,
            "raw_requested_atomic": int(INITIAL_ISSUANCE_PER_EPOCH),
            "issued_atomic": near_cap_amount,
            "remaining_after_atomic": near_cap_remaining,
        },
    }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default=str(OUT_PATH))
    ap.add_argument("--sample-epochs", type=int, default=12)
    ap.add_argument("--check", action="store_true")
    args = ap.parse_args()
    out = Path(args.out)
    data = json.dumps(build_payload(args.sample_epochs), indent=2, sort_keys=True, ensure_ascii=False) + "\n"
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
