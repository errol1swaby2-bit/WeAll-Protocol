#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from rehearse_anti_sybil_suspicion_review_lifecycle_b585_v1_5 import run_harness as run_anti_sybil_lifecycle
from rehearse_helper_equivalence_corpus_b586_v1_5 import run_harness as run_helper_corpus
from rehearse_storage_ipfs_durability_b584_v1_5 import run_harness as run_storage_durability

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "generated" / "b582_b586_readiness_truth_and_proof_v1_5.json"

Json = dict[str, Any]


def _load_json(rel: str) -> Json:
    value = json.loads((ROOT / rel).read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise TypeError(f"{rel} root must be object")
    return value


def _gap_register_truth() -> Json:
    gap = _load_json("generated/v15_implementation_gap_register.json")
    entries = {item.get("id"): item for item in gap.get("remaining_p0_p1_gaps", []) if isinstance(item, dict)}
    state = entries.get("P1-STATE-ROOT-VECTORS", {})
    econ = entries.get("P1-ECONOMIC-SIMULATION-PACK", {})
    return {
        "ok": bool(
            state.get("status") == "initial_vector_pack_added_needs_cross_machine_release_vectors"
            and econ.get("status") == "initial_simulation_added_activation_still_blocked"
            and "generated/state_root_vectors_v1_5.json" in state.get("evidence", [])
            and "generated/tokenomics_simulation_v1_5.json" in econ.get("evidence", [])
        ),
        "batch": "582",
        "state_root_vector_gap_status": state.get("status"),
        "economic_simulation_gap_status": econ.get("status"),
        "state_root_next_gate": state.get("next_gate"),
        "economic_simulation_next_gate": econ.get("next_gate"),
        "public_beta_ready_claimed": False,
        "live_economics_claimed": False,
        "public_validator_readiness_claimed": False,
    }


def _operator_route_metadata_truth() -> Json:
    contract = _load_json("generated/api_contract_map_v1_5.json")
    routes = {f"{r.get('method')} {r.get('path')}": r for r in contract.get("routes", []) if isinstance(r, dict)}
    wanted = [
        "POST /v1/poh/operator/live/init",
        "POST /v1/poh/operator/live/finalize",
        "POST /v1/poh/operator/tier2/finalize",
    ]
    records = {key: routes.get(key, {}) for key in wanted}
    ok = all(
        record.get("metadata_source") == "specs/api_contracts/v1_5_route_metadata.json"
        and record.get("auth") == "poh_operator_token_required_env_gated"
        and "public validator" in str(record.get("truth_boundary", "")).lower()
        for record in records.values()
    )
    return {
        "ok": ok,
        "batch": "583",
        "operator_routes": records,
        "operator_route_count": len(records),
        "operator_routes_explicit_metadata": ok,
        "operator_routes_public_validator_authority_claimed": False,
        "operator_routes_public_poh_finalization_claimed": False,
    }


def build() -> Json:
    gap_truth = _gap_register_truth()
    operator_metadata = _operator_route_metadata_truth()
    storage = run_storage_durability()
    anti_sybil = run_anti_sybil_lifecycle()
    helper = run_helper_corpus()
    boundaries = {
        "automatic_protocol_upgrades": False,
        "complete_anti_sybil_solved": False,
        "live_economics": False,
        "mainnet_readiness": False,
        "personalized_feed_ranking": False,
        "production_helper_execution": False,
        "public_beta_readiness": False,
        "public_decentralized_media_durability": False,
        "public_multi_validator_bft": False,
        "public_storage_provider_market": False,
        "public_validator_readiness": False,
    }
    return {
        "schema": "weall.v1_5.batch582_586.readiness_truth_and_proof",
        "batch_range": "582-586",
        "ok": all(bool(x.get("ok")) for x in (gap_truth, operator_metadata, storage, anti_sybil, helper)),
        "gap_register_truth_refresh": gap_truth,
        "poh_operator_route_metadata": operator_metadata,
        "storage_ipfs_durability_rehearsal": storage,
        "anti_sybil_suspicion_review_lifecycle": anti_sybil,
        "helper_equivalence_corpus_expansion": helper,
        "controlled_testnet_candidate_strengthened": True,
        "trusted_observer_candidate_strengthened": True,
        "public_beta_ready": False,
        "claim_boundaries": boundaries,
        "remaining_gaps": [
            "State-root vectors and tokenomics simulation now have accurate gap-register status, but public beta still needs cross-machine vectors and deeper economics adversarial analysis.",
            "PoH operator routes now have explicit metadata, but operator routes remain env/token gated and do not grant public validator or public PoH authority.",
            "Storage durability now rejects wrong/corrupt content and retrieves from a non-origin local daemon-compatible process, but public decentralized media durability still requires multi-machine operator proof.",
            "Anti-Sybil suspicion records now flow through panel/adjudication/recovery/deletion rehearsals, but complete Sybil resistance and automatic duplicate-human detection remain unclaimed.",
            "Helper equivalence corpus evidence expanded without activating production helper execution; multi-node helper production proof remains required.",
        ],
    }


def _canon(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, indent=2) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    artifact = build()
    text = _canon(artifact)
    if args.check:
        if not OUT.exists() or OUT.read_text(encoding="utf-8") != text:
            raise SystemExit("b582_b586_readiness_truth_and_proof_v1_5.json is stale; rerun generator")
        print(f"OK: {OUT.relative_to(ROOT)} is fresh")
        return 0
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(text, encoding="utf-8")
    print(str(OUT))
    return 0 if artifact.get("ok") else 1


if __name__ == "__main__":
    raise SystemExit(main())
