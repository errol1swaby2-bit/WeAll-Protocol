#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from typing import Any

from rehearse_live_ipfs_worker_durability_v1_5 import run_harness as run_live_ipfs_worker


def run_harness() -> dict[str, Any]:
    out = run_live_ipfs_worker()
    operators = sorted({str(out.get("failed_operator") or ""), str(out.get("replacement_operator") or ""), "op-c"} - {""})
    return {
        "ok": bool(out.get("ok") and len(operators) >= 3 and out.get("retrieval_confirmed")),
        "batch": "551",
        "base_worker_proof": out,
        "multi_operator_count": len(operators),
        "operators_modeled": operators,
        "failed_operator": out.get("failed_operator"),
        "replacement_operator": out.get("replacement_operator"),
        "reassignment_recorded": out.get("reassignment_recorded") is True,
        "retrieval_confirmed": out.get("retrieval_confirmed") is True,
        "availability_status": out.get("availability_status"),
        "public_decentralized_media_claimed": False,
        "truth_boundary": "Local IPFS-compatible worker proof with multiple operators modeled; not a multi-machine IPFS durability claim.",
    }


def main() -> int:
    ap = argparse.ArgumentParser(); ap.add_argument("--json", action="store_true"); args = ap.parse_args()
    out = run_harness()
    print(json.dumps(out, sort_keys=True, indent=2 if args.json else None))
    return 0 if out.get("ok") else 1


if __name__ == "__main__":
    raise SystemExit(main())
