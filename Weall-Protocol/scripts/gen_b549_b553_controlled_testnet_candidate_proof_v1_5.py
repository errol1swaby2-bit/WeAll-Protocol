#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from rehearse_antis_sybil_evidence_retention_recovery_v1_5 import run_harness as run_retention
from rehearse_long_lived_validator_network_skeleton_v1_5 import run_harness as run_validator_network
from rehearse_multi_operator_storage_durability_v1_5 import run_harness as run_storage
from rehearse_poh_challenge_public_write_v1_5 import run_harness as run_poh_challenge_api

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "generated" / "b549_b553_controlled_testnet_candidate_proof_v1_5.json"


def build() -> dict[str, Any]:
    poh_api = run_poh_challenge_api()
    validator = run_validator_network()
    storage = run_storage()
    retention = run_retention()
    claim_boundaries = {
        "public_validator_readiness": False,
        "public_multi_validator_bft": False,
        "live_economics": False,
        "automatic_protocol_upgrades": False,
        "production_helper_execution": False,
        "mainnet_readiness": False,
        "complete_anti_sybil_solved": False,
        "personalized_feed_ranking": False,
    }
    remaining = [
        "public validator readiness still requires long-running full production BFT gossip/QC/mempool multi-node proof",
        "storage durability proof is local IPFS-compatible worker/operator rehearsal, not a public multi-machine IPFS network",
        "PoH challenge public write path is available, but duplicate-human and reviewer-collusion detection are not fully solved",
        "live economics remains locked pending reward-farming, wallet, treasury, legal, and long-run simulation review",
        "production helper execution remains disabled pending full serial-equivalence and adversarial multi-node proof",
    ]
    return {
        "schema": "weall.v1_5.batch549_553.controlled_testnet_candidate_proof",
        "ok": all(bool(x.get("ok")) for x in (poh_api, validator, storage, retention)),
        "batch_range": "549-553",
        "poh_challenge_public_write": poh_api,
        "long_lived_validator_network_skeleton": validator,
        "multi_operator_storage_durability": storage,
        "anti_sybil_evidence_retention_recovery": retention,
        "controlled_testnet_candidate_evidence": {
            "poh_challenge_public_client_gap_closed": bool(poh_api.get("public_client_write_gap_closed")),
            "validator_rehearsal_node_count": int(validator.get("node_count") or 0),
            "storage_operator_count": int(storage.get("multi_operator_count") or 0),
            "evidence_retention_policy_present": bool(retention.get("retention_after_reverification")),
            "controlled_testnet_rehearsal_candidate": True,
            "public_beta_ready": False,
        },
        "claim_boundaries": claim_boundaries,
        "remaining_public_testnet_gaps": remaining,
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
            raise SystemExit("b549_b553_controlled_testnet_candidate_proof_v1_5.json is stale; rerun generator")
        print(f"OK: {OUT.relative_to(ROOT)} is fresh")
        return 0
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(text, encoding="utf-8")
    print(str(OUT))
    return 0 if artifact.get("ok") else 1


if __name__ == "__main__":
    raise SystemExit(main())
