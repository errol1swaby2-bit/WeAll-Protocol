#!/usr/bin/env python3
"""
Generate deterministic tx_index.json from specs/tx_canon/tx_canon.yaml.
"""

from __future__ import annotations

import argparse

from weall.tx.canon import generate_tx_index_json


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--spec", default="specs/tx_canon/tx_canon.yaml")
    ap.add_argument("--out", default="generated/tx_index.json")
    args = ap.parse_args()

    result = generate_tx_index_json(spec_path=args.spec, out_path=args.out)
    print(f"✅ wrote {result.path} ({result.tx_count} tx types)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
