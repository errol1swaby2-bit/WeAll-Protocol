#!/usr/bin/env python3
from __future__ import annotations

"""Fail closed if removed third-tier PoH vocabulary or state writes reappear.

This guard is intentionally string-based. It catches docs, generated canon files,
runtime code, tests, scripts, and frontend copy before compatibility language can
creep back into the two-tier rebuild.
"""

from pathlib import Path
import os
import sys

REMOVED_TIER = "TIER" + "3"
REMOVED_TX_PREFIX = "POH_" + REMOVED_TIER + "_"
REMOVED_BOOTSTRAP = "POH_BOOTSTRAP_" + REMOVED_TIER + "_GRANT"

DISALLOWED_PATTERNS = (
    "Tier" + "3",
    "tier" + "3",
    REMOVED_TIER,
    "Tier-" + "3",
    "tier-" + "3",
    REMOVED_TX_PREFIX,
    REMOVED_BOOTSTRAP,
    '"poh_tier": ' + "3",
    "'poh_tier': " + "3",
    "poh_tier = " + "3",
    "poh_tier=" + "3",
    'acct["poh_tier"] = ' + "3",
    "target_tier: " + "3",
    "target_tier = " + "3",
    "target_tier=" + "3",
)

SKIP_DIRS = {
    ".git",
    ".venv",
    "venv",
    "node_modules",
    "__pycache__",
    ".pytest_cache",
    ".mypy_cache",
    ".ruff_cache",
    "dist",
    "build",
    ".weall-devnet",
    ".weall-local-secrets",
    "data",
}

SKIP_DIR_SUFFIXES = (
    ".aux_helper_lanes",
)

SKIP_SUFFIXES = {
    ".pyc",
    ".png",
    ".jpg",
    ".jpeg",
    ".gif",
    ".ico",
    ".sqlite",
    ".db",
    ".zip",
    ".gz",
    ".tar",
    ".tgz",
    ".woff",
    ".woff2",
    ".ttf",
}


def _repo_root() -> Path:
    here = Path(__file__).resolve()
    return here.parents[1]


def _should_skip(path: Path) -> bool:
    if any(part in SKIP_DIRS for part in path.parts):
        return True
    if any(part.endswith(SKIP_DIR_SUFFIXES) for part in path.parts):
        return True
    if path.suffix.lower() in SKIP_SUFFIXES:
        return True
    return False


def main() -> int:
    root = _repo_root()
    offenders: list[tuple[str, int, str, str]] = []

    for dirpath, dirnames, filenames in os.walk(root):
        current = Path(dirpath)
        dirnames[:] = sorted(
            d
            for d in dirnames
            if d not in SKIP_DIRS and not d.endswith(SKIP_DIR_SUFFIXES)
        )
        for filename in sorted(filenames):
            path = current / filename
            if _should_skip(path):
                continue
            try:
                text = path.read_text(encoding="utf-8")
            except UnicodeDecodeError:
                continue

            rel = str(path.relative_to(root))
            for line_no, line in enumerate(text.splitlines(), 1):
                for pattern in DISALLOWED_PATTERNS:
                    if pattern in line:
                        offenders.append((rel, line_no, pattern, line.strip()))
                        break

    if offenders:
        print("ERROR: removed PoH tier vocabulary or state writes were found.")
        for rel, line_no, pattern, line in offenders[:200]:
            print(f"{rel}:{line_no}: pattern={pattern!r}: {line}")
        if len(offenders) > 200:
            print(f"... {len(offenders) - 200} more offenders omitted")
        return 1

    print("OK: two-tier PoH guard found no removed third-tier references.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
