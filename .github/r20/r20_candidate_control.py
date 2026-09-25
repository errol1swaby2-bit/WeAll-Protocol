#!/usr/bin/env python3
from __future__ import annotations

import runpy
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO_ROOT = HERE.parents[1]
PROJECT_ROOT = REPO_ROOT / "Weall-Protocol"
ORIGINAL_COMMIT = "e59f4e695be9508bf22f2675b5ed6272dd983e98"
ORIGINAL_REL = ".github/r20/r20_candidate_control.py"
ORIGINAL_BLOB = "5cacead33675cae66b46c1d6286122811d20f4b8"
TEMP_IMPL = HERE / ".r20_candidate_control_original.py"


def _load_original_main():
    actual_blob = subprocess.check_output(
        ["git", "rev-parse", f"{ORIGINAL_COMMIT}:{ORIGINAL_REL}"],
        cwd=REPO_ROOT,
        text=True,
    ).strip()
    if actual_blob != ORIGINAL_BLOB:
        raise SystemExit(
            f"known-good r20 controller blob drift: {actual_blob} != {ORIGINAL_BLOB}"
        )

    source = subprocess.check_output(
        ["git", "show", f"{ORIGINAL_COMMIT}:{ORIGINAL_REL}"],
        cwd=REPO_ROOT,
    )
    TEMP_IMPL.write_bytes(source)
    namespace = runpy.run_path(
        str(TEMP_IMPL),
        run_name="r20_candidate_control_original",
    )
    original_main = namespace.get("main")
    if not callable(original_main):
        raise SystemExit("known-good r20 controller has no callable main()")
    return original_main


def _refresh_b517_completion_proof() -> None:
    generator = PROJECT_ROOT / "scripts" / "gen_b517_b521_completion_proof_v1_5.py"
    if not generator.is_file():
        raise SystemExit(f"missing deterministic B517-B521 generator: {generator}")

    subprocess.run(
        [sys.executable, str(generator)],
        cwd=PROJECT_ROOT,
        check=True,
    )
    subprocess.run(
        [sys.executable, str(generator), "--check"],
        cwd=PROJECT_ROOT,
        check=True,
    )
    print("refreshed deterministic B517-B521 completion proof and verified --check")


def main() -> int:
    command = sys.argv[1] if len(sys.argv) > 1 else ""
    try:
        original_main = _load_original_main()
        rc = original_main()
        if rc not in (None, 0):
            raise SystemExit(f"known-good r20 controller failed: {rc}")
        if command == "verify-state":
            _refresh_b517_completion_proof()
        return 0
    finally:
        TEMP_IMPL.unlink(missing_ok=True)


if __name__ == "__main__":
    raise SystemExit(main())
