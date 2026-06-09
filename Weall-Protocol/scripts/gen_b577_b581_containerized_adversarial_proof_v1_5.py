#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from rehearse_containerized_validator_network_v1_5 import run_harness as run_containerized_validator
from rehearse_extended_seeded_network_soak_v1_5 import run_harness as run_extended_soak
from rehearse_real_ipfs_daemon_durability_v1_5 import run_harness as run_real_ipfs_daemon
from rehearse_anti_sybil_conflict_appeal_recovery_v1_5 import run_harness as run_anti_sybil_conflict_appeal
from rehearse_economics_sybil_farming_adversarial_stress_v1_5 import run_harness as run_economics_sybil_stress

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "generated" / "b577_b581_containerized_adversarial_proof_v1_5.json"

Json = dict[str, Any]


def build() -> Json:
    validator = run_containerized_validator()
    soak = run_extended_soak()
    storage = run_real_ipfs_daemon()
    anti_sybil = run_anti_sybil_conflict_appeal()
    economics = run_economics_sybil_stress()
    boundaries = {
        "automatic_protocol_upgrades": False,
        "complete_anti_sybil_solved": False,
        "live_economics": False,
        "mainnet_readiness": False,
        "personalized_feed_ranking": False,
        "production_helper_execution": False,
        "public_multi_validator_bft": False,
        "public_validator_readiness": False,
    }
    return {
        "schema": "weall.v1_5.batch577_581.containerized_adversarial_proof",
        "batch_range": "577-581",
        "ok": all(bool(x.get("ok")) for x in (validator, soak, storage, anti_sybil, economics)),
        "containerized_validator_network": validator,
        "extended_seeded_network_soak": soak,
        "real_ipfs_daemon_durability": storage,
        "anti_sybil_conflict_appeal_recovery": anti_sybil,
        "economics_sybil_farming_adversarial_stress": economics,
        "private_testnet_candidate_strengthened": True,
        "public_beta_ready": False,
        "claim_boundaries": boundaries,
        "remaining_gaps": [
            "validator rehearsal now uses independent local process roots and bound ports, but public validator readiness still requires independent operators and longer multi-machine rehearsal",
            "IPFS durability now attempts a real Kubo daemon when available and records a daemon-compatible fallback in CI, so public decentralized media durability remains unclaimed unless real daemon mode is used in operator rehearsal",
            "anti-Sybil signal aggregation now excludes conflicts and supports appeals, but automatic duplicate-human/collusion detection remains unclaimed",
            "economics Sybil/farming stress remains locked and read-model only; live economics still requires governance/legal/wallet/treasury review",
        ],
    }


def _canon(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, indent=2) + "\n"


def main() -> int:
    ap = argparse.ArgumentParser(); ap.add_argument("--check", action="store_true"); args = ap.parse_args()
    artifact = build(); text = _canon(artifact)
    if args.check:
        if not OUT.exists() or OUT.read_text(encoding="utf-8") != text:
            raise SystemExit("b577_b581_containerized_adversarial_proof_v1_5.json is stale; rerun generator")
        print(f"OK: {OUT.relative_to(ROOT)} is fresh")
        return 0
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(text, encoding="utf-8")
    print(str(OUT))
    return 0 if artifact.get("ok") else 1

if __name__ == "__main__":
    raise SystemExit(main())
