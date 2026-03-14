#!/usr/bin/env python3
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

OUT = Path("generated/tx_index.json")


def _in_git_repo() -> bool:
    """Return True if we're in a git work tree (and git is available)."""
    try:
        r = subprocess.run(
            ["git", "rev-parse", "--is-inside-work-tree"],
            capture_output=True,
            text=True,
            check=False,
        )
        return r.returncode == 0 and r.stdout.strip().lower() == "true"
    except FileNotFoundError:
        return False


def main() -> None:
    # In a git checkout we can rely on `git diff`.
    # In non-git contexts (e.g., zip exports) we fall back to a byte-compare
    # against the pre-generation file so this check remains meaningful.
    before: bytes | None = None
    if not _in_git_repo() and OUT.exists():
        before = OUT.read_bytes()

    # Re-generate
    subprocess.check_call([sys.executable, "scripts/gen_tx_index.py"])

    if _in_git_repo():
        r = subprocess.run(
            ["git", "diff", "--exit-code", "--", str(OUT)],
            capture_output=True,
            text=True,
        )
        if r.returncode != 0:
            print("❌ generated/tx_index.json is out of date. Run: python3 scripts/gen_tx_index.py")
            if r.stdout.strip():
                print(r.stdout)
            if r.stderr.strip():
                print(r.stderr)
            sys.exit(1)

        print("✅ generated/tx_index.json is up to date.")
        return

    # Non-git fallback
    if before is not None and before != OUT.read_bytes():
        print("❌ generated/tx_index.json changed during regeneration.")
        print("   (No git checkout detected, so cannot run `git diff`.)")
        print("   Run: python3 scripts/gen_tx_index.py and commit the updated file.")
        sys.exit(1)

    print("✅ generated/tx_index.json is up to date (non-git check).")


if __name__ == "__main__":
    main()
