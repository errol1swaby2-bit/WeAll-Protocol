#!/usr/bin/env python3
"""Audit test-suite naming professionalization.

This helper is intentionally read-only by default. It checks the current
working-tree view, not only the committed index, so rename patches can be
validated before staging.
"""

from __future__ import annotations

import argparse
import os
import re
import subprocess
from pathlib import Path
from typing import Sequence

BATCH_NAME_RE = re.compile(r"(test_batch[0-9]|_batch[0-9]|batch[0-9][a-z]?)", re.IGNORECASE)

REVIEWER_REFERENCE_RE = re.compile(
    r"(test_batch[0-9]|_batch[0-9]|batch[0-9][a-z]?.*\.py)",
    re.IGNORECASE,
)

APPROVED_REFERENCE_PATHS = {
    "Weall-Protocol/docs/TEST_RENAME_MAP.md",
    "Weall-Protocol/docs/TEST_REDUNDANCY_REVIEW.md",
    "Weall-Protocol/docs/PROFESSIONALIZATION_BACKLOG.md",
}

REFERENCE_ROOTS = (
    "README.md",
    "RELEASE_CHECKLIST.md",
    "CONTRIBUTING.md",
    "SECURITY.md",
    "Weall-Protocol/docs",
    "Weall-Protocol/scripts",
    "scripts",
    "audit-metadata",
    ".github",
)


def repo_root() -> Path:
    result = subprocess.run(
        ["git", "rev-parse", "--show-toplevel"],
        check=True,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    return Path(result.stdout.strip())


def _run_git(args: list[str], cwd: Path) -> list[str]:
    result = subprocess.run(
        ["git", *args],
        cwd=cwd,
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    raw = result.stdout
    if not raw:
        return []
    return [item.decode("utf-8") for item in raw.split(b"\0") if item]


def working_tree_files(root: Path | None = None) -> list[str]:
    """Return tracked plus untracked files, excluding working-tree deletions."""

    root = root or repo_root()
    files = set(_run_git(["ls-files", "-z", "--cached", "--others", "--exclude-standard"], root))
    deleted = set(_run_git(["ls-files", "-z", "--deleted"], root))
    return sorted(files - deleted)


def batch_named_test_files(root: Path | None = None) -> list[str]:
    root = root or repo_root()
    matches: list[str] = []

    for path in working_tree_files(root):
        file_name = os.path.basename(path)

        if not path.startswith("Weall-Protocol/tests/"):
            continue
        if not file_name.startswith("test_") or not file_name.endswith(".py"):
            continue
        if BATCH_NAME_RE.search(file_name):
            matches.append(path)

    return sorted(matches)


def reviewer_facing_batch_references(root: Path | None = None) -> list[str]:
    root = root or repo_root()
    findings: list[str] = []

    for path in working_tree_files(root):
        if path in APPROVED_REFERENCE_PATHS:
            continue
        if not any(path == prefix or path.startswith(prefix.rstrip("/") + "/") for prefix in REFERENCE_ROOTS):
            continue

        full_path = root / path
        if not full_path.is_file():
            continue

        try:
            text = full_path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue

        for line_number, line in enumerate(text.splitlines(), start=1):
            if REVIEWER_REFERENCE_RE.search(line):
                findings.append(f"{path}:{line_number}:{line.strip()}")

    return sorted(findings)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--check",
        action="store_true",
        help="fail if active batch-named pytest files or reviewer-facing references remain",
    )
    args = parser.parse_args(argv)

    batch_files = batch_named_test_files()
    references = reviewer_facing_batch_references()

    if batch_files:
        print("Batch-named pytest files remain:")
        for path in batch_files:
            print(f"  {path}")
    else:
        print("OK: no active batch-named pytest files remain")

    if references:
        print("Reviewer-facing batch test references remain:")
        for finding in references:
            print(f"  {finding}")
    else:
        print("OK: no reviewer-facing batch test references remain")

    if args.check and (batch_files or references):
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
