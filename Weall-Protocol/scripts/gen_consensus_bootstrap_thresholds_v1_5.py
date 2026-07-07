#!/usr/bin/env python3
from __future__ import annotations

"""Generate/check public-testnet consensus bootstrap threshold evidence."""

import argparse
import json
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
OUT = ROOT / "generated" / "consensus_bootstrap_thresholds_v1_5.json"
Json = dict[str, Any]


def _pretty(obj: Any) -> str:
    return json.dumps(obj, indent=2, sort_keys=True, ensure_ascii=False) + "\n"


def _flow_status(active_validators: int) -> Json:
    from weall.runtime.bft_hotstuff import BFT_MIN_VALIDATORS, normalize_consensus_phase, quorum_threshold

    phase = normalize_consensus_phase(active_validators)
    return {
        "active_validator_count": active_validators,
        "consensus_phase": phase,
        "hotstuff_bft_active": active_validators >= BFT_MIN_VALIDATORS,
        "quorum_threshold": quorum_threshold(active_validators) if active_validators > 0 else 0,
        "can_process_observer_only_flows": True,
        "can_process_adaptive_poh_bootstrap_before_bft": active_validators < BFT_MIN_VALIDATORS,
        "can_finalize_hotstuff_bft_blocks": active_validators >= BFT_MIN_VALIDATORS,
        "blocked_before_bft_threshold": [
            "production_hotstuff_finality_claims",
            "public_validator_bft_claims",
            "mainnet_or_production_economics_claims",
        ] if active_validators < BFT_MIN_VALIDATORS else [],
    }


def build() -> Json:
    from weall.runtime.bft_hotstuff import (
        BFT_MIN_VALIDATORS,
        CONSENSUS_ALGORITHM,
        FINALITY_RULE,
        LEADER_SELECTION_RULE,
        QUORUM_RULE,
        quorum_threshold,
    )

    counts = [_flow_status(n) for n in range(0, 8)]
    return {
        "schema": "weall.v1_5.consensus_bootstrap_thresholds",
        "version": "2026-06-public-genesis-launch",
        "algorithm": CONSENSUS_ALGORITHM,
        "leader_selection_rule": LEADER_SELECTION_RULE,
        "quorum_rule": QUORUM_RULE,
        "finality_rule": FINALITY_RULE,
        "bft_min_validators": BFT_MIN_VALIDATORS,
        "quorum_examples": {str(n): quorum_threshold(n) if n > 0 else 0 for n in range(0, 8)},
        "bootstrap_rules": {
            "only_genesis_seed_online": "observer/onboarding/status/bootstrap flows may proceed; production HotStuff BFT claims remain blocked",
            "one_additional_validator": "multi-validator bootstrap phase; still below BFT_MIN_VALIDATORS",
            "two_additional_validators": "multi-validator bootstrap phase; still below BFT_MIN_VALIDATORS when total active validators is 3",
            "bft_becomes_active": f"when active validator count is at least {BFT_MIN_VALIDATORS}",
            "maintainer_manual_activation_authority": False,
            "trust_roots_mutated_by_validators": False,
        },
        "counts": counts,
        "source_files": [
            "src/weall/runtime/bft_hotstuff.py",
            "src/weall/runtime/bft_runtime_adapter.py",
            "src/weall/runtime/poh/bootstrap_quorum.py",
            "tests/test_validator_set_activation_boundary.py",
        ],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate/check consensus bootstrap thresholds artifact.")
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
            raise SystemExit(f"stale generated consensus bootstrap thresholds: {OUT.relative_to(ROOT)}")
        print(f"OK: {OUT.relative_to(ROOT)} is current")
        return 0
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(text, encoding="utf-8")
    print(f"wrote {OUT.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
