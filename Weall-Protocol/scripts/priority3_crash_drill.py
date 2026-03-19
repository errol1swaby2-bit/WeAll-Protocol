from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def main() -> int:
    ap = argparse.ArgumentParser(description="Run the Priority 3 crash-boundary regression drills.")
    ap.add_argument("--pytest-args", default="", help="Additional pytest args to append.")
    args = ap.parse_args()

    cmd = [
        sys.executable,
        "-m",
        "pytest",
        "-q",
        str(_repo_root() / "tests" / "test_priority3_crash_boundaries_batch27.py"),
    ]
    if args.pytest_args.strip():
        cmd.extend(args.pytest_args.strip().split())
    proc = subprocess.run(cmd, cwd=str(_repo_root()))
    summary = {"ok": proc.returncode == 0, "returncode": int(proc.returncode), "command": cmd}
    print(json.dumps(summary, indent=2, sort_keys=True))
    return int(proc.returncode)


if __name__ == "__main__":
    raise SystemExit(main())
