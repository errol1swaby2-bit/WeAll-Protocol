#!/usr/bin/env python3
"""Generate or read-only check deterministic tx_index.json from tx canon."""

from __future__ import annotations

import argparse
import tempfile
from pathlib import Path

from weall.tx.canon import generate_tx_index_json


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--spec", default="specs/tx_canon/tx_canon.yaml")
    ap.add_argument("--out", default="generated/tx_index.json")
    ap.add_argument(
        "--check",
        action="store_true",
        help="generate to a temporary path and compare without modifying --out",
    )
    args = ap.parse_args()

    out = Path(args.out)
    if args.check:
        with tempfile.TemporaryDirectory(prefix="weall_tx_index_check_") as tmp:
            candidate = Path(tmp) / "tx_index.json"
            result = generate_tx_index_json(spec_path=args.spec, out_path=str(candidate))
            if not out.exists() or out.read_bytes() != candidate.read_bytes():
                print(
                    "❌ generated/tx_index.json is out of date. "
                    "Run: python3 scripts/gen_tx_index.py"
                )
                return 1
            print(f"✅ {out} is up to date ({result.tx_count} tx types).")
            return 0

    result = generate_tx_index_json(spec_path=args.spec, out_path=args.out)
    print(f"✅ wrote {result.path} ({result.tx_count} tx types)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
