#!/usr/bin/env python3
from __future__ import annotations

import subprocess
import sys


def main() -> None:
    """Verify generated tx-index freshness without mutating the candidate tree."""

    proc = subprocess.run(
        [sys.executable, "scripts/gen_tx_index.py", "--check"],
        text=True,
        check=False,
    )
    if proc.returncode != 0:
        raise SystemExit(proc.returncode)
    print("✅ generated/tx_index.json is up to date (read-only check).")


if __name__ == "__main__":
    main()
