#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path

from weall.runtime.fault_injection import run_priority1_heavy_soak


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Run the longer priority-1 adversarial soak batch: BFT rejoin/partition plus SQLite writer pressure and mempool spam."
    )
    ap.add_argument("--work-dir", default="", help="Base directory for outputs. Defaults to a temp dir.")
    ap.add_argument("--chain-id-prefix", default="priority1-heavy")
    ap.add_argument("--tx-index-path", default="")
    args = ap.parse_args()

    summary = run_priority1_heavy_soak(
        work_dir=str(Path(args.work_dir).resolve()) if str(args.work_dir).strip() else None,
        chain_id_prefix=str(args.chain_id_prefix),
        tx_index_path=str(args.tx_index_path or "") or None,
    )
    print(json.dumps(summary.to_json(), sort_keys=True, indent=2))
    return 0 if summary.ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
