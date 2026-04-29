#!/usr/bin/env python3
from __future__ import annotations

import json
import sys
from pathlib import Path


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def _bootstrap_path() -> None:
    root = _repo_root()
    src = root / "src"
    if str(src) not in sys.path:
        sys.path.insert(0, str(src))


def main() -> int:
    _bootstrap_path()
    from weall.runtime.tx_contracts import tx_contract_summary

    root = _repo_root()
    out_path = root / "generated" / "tx_contract_map.json"
    out_path.parent.mkdir(parents=True, exist_ok=True)
    payload = tx_contract_summary()
    out_path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"wrote {out_path}")
    print(
        "summary:",
        json.dumps(
            {
                "tx_count": payload["tx_count"],
                "schema_covered_count": payload["schema_covered_count"],
                "unclaimed_count": payload["unclaimed_count"],
                "duplicate_claim_count": payload["duplicate_claim_count"],
            },
            sort_keys=True,
        ),
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
