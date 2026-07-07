#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from rehearse_anti_sybil_escalation_recovery_windows_v1_5 import run_harness as run_anti_sybil_windows
from rehearse_economics_farming_simulation_locked_v1_5 import run_harness as run_economics_farming
from rehearse_live_peer_catchup_from_follower_state_v1_5 import run_harness as run_follower_sync
from rehearse_storage_worker_failure_retry_loop_v1_5 import run_harness as run_storage_retry
from rehearse_validator_follower_apply_hardening_v1_5 import run_harness as run_validator_apply

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "generated" / "b562_b566_mechanics_hardening_proof_v1_5.json"


def build() -> dict[str, Any]:
    validator = run_validator_apply()
    follower_sync = run_follower_sync()
    storage_retry = run_storage_retry()
    anti_sybil = run_anti_sybil_windows()
    economics = run_economics_farming()
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
        "schema": "weall.v1_5.batch562_566.mechanics_hardening_proof",
        "ok": all(bool(x.get("ok")) for x in (validator, follower_sync, storage_retry, anti_sybil, economics)),
        "batch_range": "562-566",
        "validator_follower_apply_hardening": validator,
        "live_peer_catchup_from_follower_state": follower_sync,
        "storage_worker_failure_retry_loop": storage_retry,
        "anti_sybil_escalation_recovery_windows": anti_sybil,
        "economics_farming_simulation_locked": economics,
        "controlled_testnet_candidate_strengthened": True,
        "public_beta_ready": False,
        "claim_boundaries": boundaries,
        "remaining_gaps": [
            "public validator readiness still requires independent long-running validators with full production BFT gossip under adversarial timing",
            "peer catch-up is now sourced from follower state, but still needs multi-machine network churn rehearsal",
            "storage retry loop is deterministic and multi-operator local, but public media durability still needs multi-daemon/multi-machine IPFS rehearsal",
            "anti-Sybil escalation/recovery windows exist, but duplicate-human detection and collusion adjudication are not solved",
            "economics farming guardrails are simulated under locked activation policy; live economics remains disabled pending legal/treasury/long-run review",
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
            raise SystemExit("b562_b566_mechanics_hardening_proof_v1_5.json is stale; rerun generator")
        print(f"OK: {OUT.relative_to(ROOT)} is fresh")
        return 0
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(text, encoding="utf-8")
    print(str(OUT))
    return 0 if artifact.get("ok") else 1


if __name__ == "__main__":
    raise SystemExit(main())
