#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from rehearse_independent_process_validator_network_v1_5 import run_harness as run_independent_validator
from rehearse_seeded_long_run_gossip_soak_v1_5 import run_harness as run_long_soak
from rehearse_multidaemon_ipfs_durability_v1_5 import run_harness as run_multidaemon_ipfs
from rehearse_anti_sybil_panel_signal_aggregation_v1_5 import run_harness as run_anti_sybil_panel
from rehearse_long_run_locked_economics_stress_v1_5 import run_harness as run_economics_stress

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "generated" / "b572_b576_multimachine_soak_proof_v1_5.json"


def build() -> dict[str, Any]:
    validator = run_independent_validator()
    soak = run_long_soak()
    storage = run_multidaemon_ipfs()
    anti_sybil = run_anti_sybil_panel()
    economics = run_economics_stress()
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
        "schema": "weall.v1_5.batch572_576.multimachine_soak_proof",
        "batch_range": "572-576",
        "ok": all(bool(x.get("ok")) for x in (validator, soak, storage, anti_sybil, economics)),
        "independent_process_validator_network": validator,
        "seeded_long_run_gossip_soak": soak,
        "multidaemon_ipfs_durability": storage,
        "anti_sybil_panel_signal_aggregation": anti_sybil,
        "long_run_locked_economics_stress": economics,
        "controlled_testnet_candidate_strengthened": True,
        "public_beta_ready": False,
        "claim_boundaries": boundaries,
        "remaining_gaps": [
            "validator rehearsal now uses independent local processes and seeded soak, but public validator readiness still requires multi-machine independent operators and production transport hardening",
            "storage durability now uses multi-daemon IPFS-compatible processes, but public decentralized media claims still require true multi-machine/IPFS deployment rehearsal",
            "anti-Sybil signal aggregation and panel selection exist, but automatic duplicate-human detection remains unclaimed",
            "economics long-run locked stress exists, but live economics requires legal, wallet, treasury, and governance activation review",
        ],
    }


def _canon(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, indent=2) + "\n"


def main() -> int:
    ap = argparse.ArgumentParser(); ap.add_argument("--check", action="store_true"); args = ap.parse_args()
    artifact = build()
    text = _canon(artifact)
    if args.check:
        if not OUT.exists() or OUT.read_text(encoding="utf-8") != text:
            raise SystemExit("b572_b576_multimachine_soak_proof_v1_5.json is stale; rerun generator")
        print(f"OK: {OUT.relative_to(ROOT)} is fresh")
        return 0
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(text, encoding="utf-8")
    print(str(OUT))
    return 0 if artifact.get("ok") else 1

if __name__ == "__main__":
    raise SystemExit(main())
