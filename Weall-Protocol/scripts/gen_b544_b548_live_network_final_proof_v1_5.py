#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from rehearse_api_system_lifecycle_closure_v1_5 import run_harness as run_lifecycle_closure
from rehearse_live_ipfs_worker_durability_v1_5 import run_harness as run_ipfs_worker
from rehearse_live_netloop_block_producer_v1_5 import run_harness as run_netloop
from rehearse_poh_dispute_adversarial_accountability_v1_5 import run_harness as run_accountability

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "generated" / "b544_b548_live_network_final_proof_v1_5.json"


def build() -> dict[str, Any]:
    netloop = run_netloop()
    lifecycle = run_lifecycle_closure()
    ipfs = run_ipfs_worker()
    accountability = run_accountability()
    claim_boundaries = {
        "public_validator_readiness": False,
        "public_multi_validator_bft": False,
        "live_economics": False,
        "automatic_protocol_upgrades": False,
        "production_helper_execution": False,
        "mainnet_readiness": False,
        "personalized_feed_ranking": False,
    }
    remaining = [
        "full long-lived multi-node P2P validator network with real BFT gossip remains required before public validator readiness",
        "poh_challenge remains the only listed public-client write gap in the API/system lifecycle closure artifact",
        "live IPFS worker proof uses a local HTTP IPFS-compatible API and should be expanded to multi-daemon/operator rehearsal before public media durability claims",
        "PoH/dispute accountability includes reviewer/juror sanctions and remedies but does not claim complete collusion or duplicate-human detection",
        "live economics remains locked pending adversarial reward-farming, treasury reporting, wallet lifecycle, legal, and long-run economic review",
    ]
    return {
        "schema": "weall.v1_5.batch544_548.live_network_final_proof",
        "ok": all(bool(x.get("ok")) for x in (netloop, lifecycle, ipfs, accountability)),
        "batch_range": "544-548",
        "live_netloop_block_producer": netloop,
        "api_system_lifecycle_closure": lifecycle,
        "live_ipfs_worker_durability": ipfs,
        "poh_dispute_adversarial_accountability": accountability,
        "claim_boundaries": claim_boundaries,
        "remaining_public_testnet_gaps": remaining,
        "private_testnet_rehearsal_candidate": True,
        "public_beta_ready": False,
    }


def _canon(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, indent=2) + "\n"


def main() -> int:
    ap = argparse.ArgumentParser(); ap.add_argument("--check", action="store_true"); args = ap.parse_args()
    artifact = build()
    text = _canon(artifact)
    if args.check:
        if not OUT.exists() or OUT.read_text(encoding="utf-8") != text:
            raise SystemExit("b544_b548_live_network_final_proof_v1_5.json is stale; rerun generator")
        print(f"OK: {OUT.relative_to(ROOT)} is fresh")
        return 0
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(text, encoding="utf-8")
    print(str(OUT))
    return 0 if artifact.get("ok") else 1


if __name__ == "__main__":
    raise SystemExit(main())
