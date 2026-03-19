#!/usr/bin/env python3
from __future__ import annotations

import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
TESTS = ROOT / "tests" / "test_priority4_invariant_fuzz_batch28.py"


def main() -> int:
    cmd = [sys.executable, "-m", "pytest", "-q", str(TESTS)]
    return subprocess.call(cmd, cwd=str(ROOT))


if __name__ == "__main__":
    raise SystemExit(main())
