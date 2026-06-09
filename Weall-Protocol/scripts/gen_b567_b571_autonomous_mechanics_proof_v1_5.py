#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from rehearse_anti_sybil_adjudication_deletion_v1_5 import run_harness as run_anti_sybil_adjudication
from rehearse_autonomous_validator_gossip_loop_v1_5 import run_harness as run_autonomous_validator
from rehearse_economics_locked_read_models_v1_5 import run_harness as run_economics_read_models
from rehearse_fresh_node_catchup_autonomous_network_v1_5 import run_harness as run_fresh_catchup
from rehearse_multiprocess_ipfs_operator_durability_v1_5 import run_harness as run_ipfs_multiprocess

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "generated" / "b567_b571_autonomous_mechanics_proof_v1_5.json"


def build() -> dict[str, Any]:
    autonomous = run_autonomous_validator()
    catchup = run_fresh_catchup()
    storage = run_ipfs_multiprocess()
    anti_sybil = run_anti_sybil_adjudication()
    economics = run_economics_read_models()
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
        "schema": "weall.v1_5.batch567_571.autonomous_mechanics_proof",
        "batch_range": "567-571",
        "ok": all(bool(x.get("ok")) for x in (autonomous, catchup, storage, anti_sybil, economics)),
        "autonomous_validator_gossip_loop": autonomous,
        "fresh_node_catchup_autonomous_network": catchup,
        "multiprocess_ipfs_operator_durability": storage,
        "anti_sybil_adjudication_deletion": anti_sybil,
        "economics_locked_read_models": economics,
        "private_testnet_candidate_strengthened": True,
        "public_beta_ready": False,
        "claim_boundaries": boundaries,
        "remaining_gaps": [
            "autonomous validator gossip is modeled in local threaded processes; public validator readiness still requires multi-machine independent operators and full production transport under adversarial timing",
            "fresh-node catch-up validates live-peer commit logs, but public network churn and malicious peer diversity require broader soak tests",
            "storage durability now uses multi-process IPFS-compatible workers, but public media durability still requires multi-daemon or multi-machine IPFS operator rehearsal",
            "anti-Sybil adjudication and evidence deletion execution exist, but automatic duplicate-human detection and legal/privacy review remain outside the current claim",
            "economics read models exist while locked; live economics remains disabled pending legal, treasury, wallet UX, and long-run economic review",
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
            raise SystemExit("b567_b571_autonomous_mechanics_proof_v1_5.json is stale; rerun generator")
        print(f"OK: {OUT.relative_to(ROOT)} is fresh")
        return 0
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(text, encoding="utf-8")
    print(str(OUT))
    return 0 if artifact.get("ok") else 1


if __name__ == "__main__":
    raise SystemExit(main())
