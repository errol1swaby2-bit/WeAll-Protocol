#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from weall.runtime.bft_hotstuff import canonical_vote_message, quorum_threshold, validator_set_hash
from weall.runtime.proposer_selection import select_proposer

Json = dict[str, Any]

VALIDATORS = ("validator-a", "validator-b", "validator-c", "validator-d")
CHAIN_ID = "weall-v15-b499-proof"
VIEW = 7
BLOCK_ID = "block-candidate-0007"
PARENT_ID = "block-candidate-0006"
BLOCK_HASH = hashlib.sha256(f"{CHAIN_ID}|{VIEW}|{BLOCK_ID}".encode()).hexdigest()


def _worker(validator: str) -> Json:
    msg = canonical_vote_message(
        chain_id=CHAIN_ID,
        view=VIEW,
        block_id=BLOCK_ID,
        block_hash=BLOCK_HASH,
        parent_id=PARENT_ID,
        signer=validator,
    )
    return {
        "process_validator": validator,
        "validator_set_hash": validator_set_hash(list(VALIDATORS)),
        "threshold": quorum_threshold(len(VALIDATORS)),
        "leader": select_proposer(active_set=list(VALIDATORS), chain_id=CHAIN_ID, height=VIEW),
        "vote_payload_sha256": hashlib.sha256(msg).hexdigest(),
        "block_id": BLOCK_ID,
        "parent_id": PARENT_ID,
        "view": int(VIEW),
    }


def run_harness() -> Json:
    rows: list[Json] = []
    script = Path(__file__).resolve()
    for validator in VALIDATORS:
        proc = subprocess.run(
            [sys.executable, str(script), "--worker", validator],
            cwd=str(ROOT),
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=True,
        )
        rows.append(json.loads(proc.stdout))

    set_hashes = sorted({str(r["validator_set_hash"]) for r in rows})
    thresholds = sorted({int(r["threshold"]) for r in rows})
    leaders = sorted({str(r["leader"]) for r in rows})
    ok = (
        len(rows) == 4
        and len(set_hashes) == 1
        and thresholds == [3]
        and len(leaders) == 1
        and len({str(r["vote_payload_sha256"]) for r in rows}) == 4
    )
    return {
        "artifact": "public_bft_multi_process_proof_v1_5",
        "public_validator_enabled": False,
        "economics_enabled": False,
        "automatic_protocol_upgrade_apply_enabled": False,
        "process_count": len(rows),
        "validator_count": len(VALIDATORS),
        "quorum_threshold": thresholds[0] if thresholds else 0,
        "validator_set_hash": set_hashes[0] if set_hashes else "",
        "leader": leaders[0] if leaders else "",
        "rows": rows,
        "ok": bool(ok),
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--json", action="store_true", help="print compact JSON")
    parser.add_argument("--worker", default="", help=argparse.SUPPRESS)
    args = parser.parse_args()
    if args.worker:
        validator = str(args.worker).strip()
        if validator not in VALIDATORS:
            print(json.dumps({"ok": False, "reason": "unknown_validator"}))
            return 2
        print(json.dumps(_worker(validator), sort_keys=True))
        return 0
    out = run_harness()
    print(json.dumps(out, sort_keys=True, indent=None if args.json else 2))
    return 0 if out.get("ok") is True else 1


if __name__ == "__main__":
    raise SystemExit(main())
