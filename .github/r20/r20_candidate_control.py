#!/usr/bin/env python3
from __future__ import annotations

import runpy
import subprocess
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO_ROOT = HERE.parents[1]
PREVIOUS_COMMIT = "259a981628e425dce876096bc1f795d20adc22d3"
PREVIOUS_REL = ".github/r20/r20_candidate_control.py"
PREVIOUS_BLOB = "1d36ba6442faa52d2bd28cf2b22056c934dcc383"
TEMP_PREVIOUS = HERE / ".r20_candidate_control_storage_closure.py"
TX0801_NEW_IMPLEMENTATION_HASH = "d3dd66310a6210918c9eb3ec9e106a6a517e2bd5ce08d2efd787c8a0c91ff821"
TX0801_OLD_IMPLEMENTATION_HASH = "d154dcebba58f1df8c5566c557a6c49d6f5763fee5c8ef711844ad37fdaf29bf"


def _load_previous_main():
    actual_blob = subprocess.check_output(
        ["git", "rev-parse", f"{PREVIOUS_COMMIT}:{PREVIOUS_REL}"],
        cwd=REPO_ROOT,
        text=True,
    ).strip()
    if actual_blob != PREVIOUS_BLOB:
        raise SystemExit(
            f"known storage-closure controller blob drift: {actual_blob} != {PREVIOUS_BLOB}"
        )
    source = subprocess.check_output(
        ["git", "show", f"{PREVIOUS_COMMIT}:{PREVIOUS_REL}"],
        cwd=REPO_ROOT,
    )
    TEMP_PREVIOUS.write_bytes(source)
    namespace = runpy.run_path(str(TEMP_PREVIOUS), run_name="r20_candidate_control_storage_closure")
    previous_main = namespace.get("main")
    if not callable(previous_main):
        raise SystemExit("known storage-closure controller has no callable main()")
    return previous_main


def main() -> int:
    try:
        previous_main = _load_previous_main()
        previous_globals = previous_main.__globals__
        original_loader = previous_globals.get("_load_original_main")
        if not callable(original_loader):
            raise SystemExit("storage-closure controller original loader contract missing")

        def _load_original_main_with_tx0801_rebind():
            original_main = original_loader()
            expected = original_main.__globals__.get("EXPECTED_SEMANTIC_REVIEWS")
            if not isinstance(expected, dict):
                raise SystemExit("original r20 semantic-review allowlist missing")
            current = expected.get("TX-0801")
            if not isinstance(current, tuple) or len(current) != 3:
                raise SystemExit(f"unexpected TX-0801 semantic-review binding: {current!r}")
            if current[0] != "IPFS_PIN_CONFIRM" or current[2] != TX0801_OLD_IMPLEMENTATION_HASH:
                raise SystemExit(f"unexpected prior TX-0801 semantic-review binding: {current!r}")
            expected["TX-0801"] = (
                current[0],
                current[1],
                TX0801_NEW_IMPLEMENTATION_HASH,
            )
            return original_main

        previous_globals["_load_original_main"] = _load_original_main_with_tx0801_rebind
        rc = previous_main()
        return int(rc or 0)
    finally:
        TEMP_PREVIOUS.unlink(missing_ok=True)


if __name__ == "__main__":
    raise SystemExit(main())
