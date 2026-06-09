#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from rehearse_production_bft_path_v1_5 import run_harness as run_bft
from rehearse_production_block_commit_replay_v1_5 import run_harness as run_replay
from rehearse_public_api_write_lifecycle_v1_5 import run_harness as run_api
from rehearse_live_storage_worker_durability_v1_5 import run_harness as run_storage

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "generated" / "b539_b543_production_path_proof_v1_5.json"


def build() -> dict[str, Any]:
    bft = run_bft()
    replay = run_replay()
    api = run_api()
    storage = run_storage()
    claim_boundaries = {
        "public_validator_readiness": False,
        "public_multi_validator_bft": False,
        "live_economics": False,
        "automatic_protocol_upgrades": False,
        "production_helper_execution": False,
        "mainnet_readiness": False,
    }
    remaining = [
        "production P2P/net-loop validator rehearsal still needed before public validators",
        "full external-client API write lifecycle still has direct-apply domains listed in api_write_lifecycle.direct_apply_write_domains_remaining",
        "live multi-daemon IPFS/operator rehearsal still needed before public media durability claims",
        "economics remains activation-complete-but-locked and must not be enabled without legal/economic review",
    ]
    return {
        "schema": "weall.v1_5.batch539_543.production_path_proof",
        "ok": all(bool(x.get("ok")) for x in (bft, replay, api, storage)),
        "batch_range": "539-543",
        "production_bft_path": bft,
        "production_block_replay": replay,
        "public_api_write_lifecycle": api,
        "live_storage_worker_durability": storage,
        "claim_boundaries": claim_boundaries,
        "remaining_public_testnet_gaps": remaining,
    }


def _canon(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, indent=2) + "\n"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--check", action="store_true")
    args = ap.parse_args()
    artifact = build()
    text = _canon(artifact)
    if args.check:
        if not OUT.exists() or OUT.read_text(encoding="utf-8") != text:
            raise SystemExit("b539_b543_production_path_proof_v1_5.json is stale; rerun generator")
        print(f"OK: {OUT.relative_to(ROOT)} is fresh")
        return 0
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(text, encoding="utf-8")
    print(str(OUT))
    return 0 if artifact.get("ok") else 1


if __name__ == "__main__":
    raise SystemExit(main())
