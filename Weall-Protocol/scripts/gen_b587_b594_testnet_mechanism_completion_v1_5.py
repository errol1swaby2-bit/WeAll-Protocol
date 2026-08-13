#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from gen_api_response_vectors_v1_5 import build as build_api_response_vectors
from rehearse_protocol_upgrade_signed_staging_b589_v1_5 import run_harness as run_upgrade_staging
from rehearse_external_multimachine_validator_harness_b590_v1_5 import run_harness as run_validator_harness
from rehearse_multimachine_storage_ipfs_durability_b591_v1_5 import run_harness as run_storage_harness
from rehearse_reviewer_accountability_appeal_b592_v1_5 import run_harness as run_reviewer_accountability
from rehearse_helper_block_path_adversarial_b593_v1_5 import run_harness as run_helper_block_path
from rehearse_locked_economics_adversarial_expansion_b594_v1_5 import run_harness as run_locked_economics
from weall.runtime.testnet_capabilities import build_testnet_capability_surface

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
    high_risk_capability_wiring_ok = all(
        capabilities.get("capabilities", {}).get(key, {}).get("enabled") is False
        for key in (
            "live_transfers",
            "live_rewards",
            "treasury_spend",
            "live_economics",
            "public_validator_join",
            "public_multi_validator_bft",
            "automatic_protocol_upgrade_apply",
            "production_helper_execution",
        )
    )
    pieces = [api_vectors, upgrade, validator, storage, reviewer, helper, economics]
    piece_ok = bool(
        high_risk_capability_wiring_ok
        and all(bool(item.get("ok")) for item in pieces)
    )
    helper_state_root_proof_complete = bool(
        helper.get("production_block_path_state_root_equivalence_proven") is True
        and helper.get("mechanism_complete") is True
    )
    mechanism_completion_ok = bool(piece_ok and helper_state_root_proof_complete)
    # The capability surface reads tracked artifacts for reviewer presentation.
    # Bind its embedded completion field to this freshly computed aggregate so
    # this generator never inherits a stale/self-referential completion claim.
    capabilities = dict(capabilities)
    capabilities["controlled_testnet_mechanisms_complete"] = mechanism_completion_ok
    required_artifacts = dict(capabilities.get("required_artifacts") or {})
    self_artifact = dict(required_artifacts.get("b587_b594_mechanism_completion") or {})
    self_artifact.update(
        {
            "path": "generated/b587_b594_testnet_mechanism_completion_v1_5.json",
            "present": True,
            "ok": mechanism_completion_ok,
            "schema": "weall.v1_5.batch587_594.testnet_mechanism_completion",
        }
    )
    required_artifacts["b587_b594_mechanism_completion"] = self_artifact
    capabilities["required_artifacts"] = required_artifacts
    artifact_blockers = [
        str(item)
        for item in list(capabilities.get("artifact_blockers") or [])
        if str(item) != "b587_b594_mechanism_completion"
    ]
    if not mechanism_completion_ok:
        artifact_blockers.append("b587_b594_mechanism_completion")
    capabilities["artifact_blockers"] = sorted(set(artifact_blockers))
    controlled_blockers = [
        str(item)
        for item in list(capabilities.get("controlled_mechanism_artifact_blockers") or [])
        if str(item) != "b587_b594_mechanism_completion"
    ]
    if not mechanism_completion_ok:
        controlled_blockers.append("b587_b594_mechanism_completion")
    capabilities["controlled_mechanism_artifact_blockers"] = sorted(set(controlled_blockers))
    # Public-beta blocker inventory is downstream/advisory to this narrower
    # mechanism-completion artifact.  Do not embed its mutable counts or
    # next-claim text here, otherwise B587 and the blocker report become
    # self-referential and generate->check stability depends on generation order.
    public_beta_advisory = dict(capabilities.get("public_beta_blocker_report") or {})
    capabilities["public_beta_blocker_report"] = {
        "present": bool(public_beta_advisory.get("present")),
        "ok": bool(public_beta_advisory.get("ok")),
        "public_beta_ready": False,
        "mainnet_ready": False,
        "advisory_to_mechanism_completion": True,
    }
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
        "ok": mechanism_completion_ok,
        "controlled_testnet_mechanisms_complete": mechanism_completion_ok,
        "controlled_testnet_ready_candidate": mechanism_completion_ok,
        "component_harnesses_ok": piece_ok,
        "high_risk_capability_wiring_ok": high_risk_capability_wiring_ok,
        "helper_state_root_proof_complete": helper_state_root_proof_complete,
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
