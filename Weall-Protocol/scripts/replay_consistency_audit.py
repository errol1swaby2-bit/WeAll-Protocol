#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from weall.runtime.replay_consistency import build_sample_chain  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Build a deterministic sample chain, replay it into a fresh ledger, "
            "and fail closed if any block/header/state-root diverges."
        )
    )
    parser.add_argument("--work-dir", required=True, help="Working directory for temp SQLite files.")
    parser.add_argument(
        "--chain-id-prefix",
        default="replay-audit",
        help="Prefix used to derive the deterministic sample chain id.",
    )
    parser.add_argument("--json", action="store_true", help="Emit compact JSON only.")
    args = parser.parse_args()

    summary = build_sample_chain(work_dir=str(Path(args.work_dir)), chain_id_prefix=args.chain_id_prefix)
    if args.json:
        print(json.dumps(summary, sort_keys=True, separators=(",", ":")))
    else:
        print(json.dumps(summary, indent=2, sort_keys=True))
    return 0 if bool(summary.get("ok")) else 1


if __name__ == "__main__":
    raise SystemExit(main())
