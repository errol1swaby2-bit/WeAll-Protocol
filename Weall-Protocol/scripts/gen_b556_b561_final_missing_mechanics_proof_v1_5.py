#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from rehearse_anti_sybil_collusion_accountability_v1_5 import run_harness as run_anti_sybil
from rehearse_economics_activation_locked_completion_v1_5 import run_harness as run_economics
from rehearse_helper_serial_equivalence_expansion_v1_5 import run_harness as run_helpers
from rehearse_live_peer_state_sync_mechanics_v1_5 import run_harness as run_state_sync
from rehearse_multi_operator_storage_workers_v1_5 import run_harness as run_storage
from rehearse_public_style_validator_network_mechanics_v1_5 import run_harness as run_validator_network

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "generated" / "b556_b561_final_missing_mechanics_proof_v1_5.json"


def build() -> dict[str, Any]:
    validator = run_validator_network()
    sync = run_state_sync()
    storage = run_storage()
    anti_sybil = run_anti_sybil()
    economics = run_economics()
    helpers = run_helpers()
    claim_boundaries = {
        "automatic_protocol_upgrades": False,
        "complete_anti_sybil_solved": False,
        "live_economics": False,
        "mainnet_readiness": False,
        "personalized_feed_ranking": False,
        "production_helper_execution": False,
        "public_multi_validator_bft": False,
        "public_validator_readiness": False,
    }
    remaining = [
        "public validator readiness still requires independently operated long-running validators with full production BFT gossip under adversarial timing",
        "state sync now proves trusted-anchor delta/resume/rejection against a running peer provider, but public peer catch-up still needs multi-machine rehearsal",
        "storage durability is multi-operator and worker-backed, but public media durability still needs real multi-daemon or multi-machine IPFS rehearsal",
        "anti-Sybil now records reviewer collusion suspicions and recovery policies, but does not solve duplicate-human or collusion adjudication",
        "economics activation preconditions can be made ready while locked, but live economics still requires adversarial farming/legal/treasury review",
        "helper equivalence corpus expanded, but production helper execution remains disabled pending full corpus and multi-node proof",
    ]
    return {
        "schema": "weall.v1_5.batch556_561.final_missing_mechanics_proof",
        "ok": all(bool(x.get("ok")) for x in (validator, sync, storage, anti_sybil, economics, helpers)),
        "batch_range": "556-561",
        "public_style_validator_network": validator,
        "live_peer_state_sync": sync,
        "multi_operator_storage_workers": storage,
        "anti_sybil_collusion_accountability": anti_sybil,
        "economics_activation_locked_completion": economics,
        "helper_serial_equivalence_expansion": helpers,
        "private_testnet_candidate_strengthened": True,
        "public_beta_ready": False,
        "claim_boundaries": claim_boundaries,
        "remaining_public_testnet_gaps": remaining,
    }


def _canon(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, indent=2) + "\n"


def main() -> int:
    ap = argparse.ArgumentParser(); ap.add_argument("--check", action="store_true"); args = ap.parse_args()
    artifact = build()
    text = _canon(artifact)
    if args.check:
        if not OUT.exists() or OUT.read_text(encoding="utf-8") != text:
            raise SystemExit("b556_b561_final_missing_mechanics_proof_v1_5.json is stale; rerun generator")
        print(f"OK: {OUT.relative_to(ROOT)} is fresh")
        return 0
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(text, encoding="utf-8")
    print(str(OUT))
    return 0 if artifact.get("ok") else 1


if __name__ == "__main__":
    raise SystemExit(main())
