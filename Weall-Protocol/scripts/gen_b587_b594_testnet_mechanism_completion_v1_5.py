#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from gen_api_response_vectors_v1_5 import build as build_api_response_vectors
from rehearse_protocol_upgrade_signed_staging_b589_v1_5 import run_harness as run_upgrade_staging
from rehearse_external_multimachine_validator_harness_b590_v1_5 import run_harness as run_validator_harness
from rehearse_multimachine_storage_ipfs_durability_b591_v1_5 import run_harness as run_storage_harness
from rehearse_reviewer_accountability_appeal_b592_v1_5 import run_harness as run_reviewer_accountability
from rehearse_helper_block_path_adversarial_b593_v1_5 import run_harness as run_helper_block_path
from rehearse_locked_economics_adversarial_expansion_b594_v1_5 import run_harness as run_locked_economics
from weall.runtime.testnet_capabilities import build_testnet_capability_surface

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "generated" / "b587_b594_testnet_mechanism_completion_v1_5.json"
Json = dict[str, Any]


def build() -> Json:
    api_vectors = build_api_response_vectors()
    capabilities = build_testnet_capability_surface({"params": {"launch_phase": "public_beta_candidate"}})
    upgrade = run_upgrade_staging()
    validator = run_validator_harness()
    storage = run_storage_harness()
    reviewer = run_reviewer_accountability()
    helper = run_helper_block_path()
    economics = run_locked_economics()
    pieces = [api_vectors, capabilities, upgrade, validator, storage, reviewer, helper, economics]
    boundaries = {
        "automatic_protocol_upgrades": False,
        "complete_anti_sybil_solved": False,
        "legal_compliance_ready": False,
        "live_economics": False,
        "mainnet_readiness": False,
        "production_helper_execution": False,
        "public_beta_readiness": False,
        "public_decentralized_media_durability": False,
        "public_multi_validator_bft": False,
        "public_storage_provider_market": False,
        "public_validator_readiness": False,
        "protocol_private_activity": False,
    }
    return {
        "schema": "weall.v1_5.batch587_594.testnet_mechanism_completion",
        "batch_range": "587-594",
        "ok": all(bool(x.get("ok", x.get("controlled_testnet_mechanisms_complete", False))) for x in pieces),
        "controlled_testnet_mechanisms_complete": True,
        "controlled_testnet_ready_candidate": True,
        "public_beta_ready": False,
        "public_readiness_claim_requires_external_gate_run": True,
        "api_response_vectors": api_vectors,
        "launch_matrix_capability_wiring": capabilities,
        "protocol_upgrade_signed_staging": upgrade,
        "external_multimachine_validator_harness": validator,
        "multimachine_storage_ipfs_durability": storage,
        "reviewer_accountability_and_appeal": reviewer,
        "helper_block_path_adversarial": helper,
        "locked_economics_adversarial_expansion": economics,
        "claim_boundaries": boundaries,
        "final_testnet_go_gate_required": [
            "run full pytest suite in repo venv",
            "run artifact freshness gates with --require-git-tracked inside real git checkout",
            "run external multi-machine validator rehearsal with independent operators or containers",
            "run storage/IPFS durability rehearsal against real daemon/operator topology",
            "review legal/compliance docs with counsel before public token/governance claims",
            "publish launch-disabled matrix and capability surface with public beta candidate docs",
        ],
        "remaining_unclaimed_after_mechanism_completion": [
            "public beta readiness until final go-gate evidence is captured",
            "public validator/BFT readiness until independent multi-machine proof passes",
            "live economics until lock, governance, legal, wallet, treasury, and adversarial economics gates pass",
            "automatic protocol upgrades until signed staging becomes deterministic migration/rollback execution in a future audited batch",
            "production helper execution until real block-path multi-node Byzantine helper proof passes",
        ],
    }


def _canon(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, indent=2) + "\n"


def main() -> int:
    ap = argparse.ArgumentParser(description="Generate/check B587-B594 testnet mechanism completion artifact.")
    ap.add_argument("--check", action="store_true")
    args = ap.parse_args()
    payload = build()
    text = _canon(payload)
    if args.check:
        if not OUT.exists() or OUT.read_text(encoding="utf-8") != text:
            raise SystemExit("b587_b594_testnet_mechanism_completion_v1_5.json is stale; rerun generator")
        print(f"OK: {OUT.relative_to(ROOT)} is fresh")
        return 0
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(text, encoding="utf-8")
    print(str(OUT))
    return 0 if payload.get("ok") else 1


if __name__ == "__main__":
    raise SystemExit(main())
