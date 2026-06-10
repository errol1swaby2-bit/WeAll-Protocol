#!/usr/bin/env python3
from __future__ import annotations

"""Generate the v1.5 public-validator/BFT preflight matrix.

This artifact is deliberately a proof checklist, not a readiness claim. It keeps
public validator promotion disabled until executable adversarial evidence exists.
"""

import argparse
import json
from pathlib import Path
from typing import Any

from weall.runtime.launch_matrix import (
    FEATURE_PUBLIC_BFT,
    FEATURE_VALIDATOR_PROMOTION,
    PHASE_PUBLIC_BETA,
    feature_status,
)

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "generated" / "public_validator_bft_preflight_matrix_v1_5.json"
Json = dict[str, Any]

SCENARIOS: list[Json] = [
    {
        "id": "bft-multiprocess-finality",
        "title": "independent multi-process validator finality",
        "required_evidence": ["process logs", "block roots", "quorum certificates", "receipt root comparison"],
        "minimum_result": "same finalized height/hash/root across honest validators",
        "current_status": "planned_or_private_rehearsal_only",
    },
    {
        "id": "minority-partition-no-finality",
        "title": "minority partition cannot finalize",
        "required_evidence": ["partition topology", "vote counts", "no-QC proof"],
        "minimum_result": "finality_threshold_not_met",
        "current_status": "must_be_captured_before_public_claim",
    },
    {
        "id": "restart-replay-root-stability",
        "title": "restart/replay preserves state root",
        "required_evidence": ["pre-restart root", "post-replay root", "receipt root audit"],
        "minimum_result": "identical roots and no skipped committed blocks",
        "current_status": "must_be_captured_before_public_claim",
    },
    {
        "id": "equivocation-rejection",
        "title": "equivocating validator evidence is rejected/accounted",
        "required_evidence": ["double proposal/vote fixture", "rejection receipt", "active set/accountability state"],
        "minimum_result": "equivocation cannot finalize conflicting blocks",
        "current_status": "must_be_captured_before_public_claim",
    },
    {
        "id": "lagging-node-catchup",
        "title": "lagging/fresh node catches up by verified replay",
        "required_evidence": ["source block range", "fresh replay transcript", "final root equality"],
        "minimum_result": "fresh node reaches same root from canonical blocks",
        "current_status": "must_be_captured_before_public_claim",
    },
    {
        "id": "observer-non-authority",
        "title": "observer cannot vote, validate, or produce blocks",
        "required_evidence": ["observer route transcript", "vote rejection", "block production rejection"],
        "minimum_result": "observer grants no validator authority",
        "current_status": "must_be_captured_before_public_claim",
    },
    {
        "id": "helper-production-disabled",
        "title": "helper execution cannot become production authority during validator proof",
        "required_evidence": ["launch matrix", "helper readiness surface", "serial fallback transcript"],
        "minimum_result": "production_helper_execution_enabled=false",
        "current_status": "guardrail_required",
    },
]


def build_payload() -> Json:
    public_bft = feature_status(PHASE_PUBLIC_BETA, FEATURE_PUBLIC_BFT)
    promotion = feature_status(PHASE_PUBLIC_BETA, FEATURE_VALIDATOR_PROMOTION)
    return {
        "schema": "weall.v1_5.public_validator_bft_preflight_matrix",
        "version": "2026-06-batch15-preflight",
        "truth_boundaries": {
            "public_validator_enabled": False,
            "public_multi_validator_bft_ready": False,
            "public_validator_promotion_enabled": bool(promotion.enabled),
            "public_bft_feature_enabled": bool(public_bft.enabled),
            "live_economics_enabled": False,
            "production_helper_execution_enabled": False,
            "artifact_is_readiness_plan_not_proof": True,
        },
        "launch_matrix_bindings": {
            "public_multi_validator_bft": public_bft.as_dict(),
            "public_validator_promotion": promotion.as_dict(),
        },
        "required_scenarios": SCENARIOS,
        "do_not_cross": [
            "do not enable public validator promotion from this artifact",
            "do not claim public BFT readiness until every required scenario has executable evidence",
            "do not enable live economics or validator payouts",
            "do not enable production helper execution",
        ],
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Generate/check public validator BFT preflight matrix.")
    parser.add_argument("--check", action="store_true")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)
    rendered = json.dumps(build_payload(), indent=2, sort_keys=True, ensure_ascii=False) + "\n"
    if args.json:
        print(rendered, end="")
        return 0
    if args.check:
        if not OUT.exists():
            raise SystemExit(f"missing generated public validator preflight matrix: {OUT.relative_to(ROOT)}")
        if OUT.read_text(encoding="utf-8") != rendered:
            raise SystemExit(f"stale generated public validator preflight matrix: {OUT.relative_to(ROOT)}")
        print(f"OK: {OUT.relative_to(ROOT)} is current")
        return 0
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(rendered, encoding="utf-8")
    print(f"wrote {OUT.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
