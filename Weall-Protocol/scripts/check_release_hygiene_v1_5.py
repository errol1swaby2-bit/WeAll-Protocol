#!/usr/bin/env python3
from __future__ import annotations

import argparse
import os
import stat
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
BACKEND = ROOT / "Weall-Protocol"

REQUIRED_EXECUTABLES = (
    ROOT / "scripts" / "run_clean_clone_go_gate_v1_5.sh",
    ROOT / "scripts" / "run_frontend_contract_check_with_backend.sh",
    BACKEND / "scripts" / "run_clean_clone_go_gate_v1_5.sh",
    BACKEND / "scripts" / "run_frontend_contract_check_with_backend.sh",
    BACKEND / "scripts" / "rehearse_release_blocker_closure_v1_5.py",
)

IGNORED_RUNTIME_PATHS = (
    "Weall-Protocol/.weall-media-cache/",
    "Weall-Protocol/.weall-devnet/",
    ".weall-dev/",
)


def _git(args: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(["git", "-C", str(ROOT), *args], text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)


def _is_executable(path: Path) -> bool:
    try:
        mode = path.stat().st_mode
    except FileNotFoundError:
        return False
    return bool(mode & stat.S_IXUSR)


def _ignored(path: str) -> bool:
    proc = _git(["check-ignore", "-q", path])
    return proc.returncode == 0


def _tracked_paths() -> list[str]:
    proc = _git(["ls-files"])
    if proc.returncode != 0:
        return []
    return [line.strip() for line in proc.stdout.splitlines() if line.strip()]


def _tracked_under(path: str, tracked: list[str]) -> list[str]:
    prefix = path.rstrip("/") + "/"
    exact = path.rstrip("/")
    return [item for item in tracked if item == exact or item.startswith(prefix)]


def main() -> int:
    ap = argparse.ArgumentParser(description="Check WeAll v1.5 release hygiene invariants.")
    ap.add_argument("--allow-dirty", action="store_true", help="Report but do not fail on a dirty worktree.")
    args = ap.parse_args()

    errors: list[str] = []
    for path in REQUIRED_EXECUTABLES:
        if not path.exists():
            errors.append(f"missing_required_executable:{path.relative_to(ROOT)}")
        elif not _is_executable(path):
            errors.append(f"not_executable:{path.relative_to(ROOT)}")

    tracked = _tracked_paths()
    for rel in IGNORED_RUNTIME_PATHS:
        probe = rel.rstrip("/") + "/.release-hygiene-probe" if rel.endswith("/") else rel
        if not _ignored(probe):
            errors.append(f"runtime_artifact_not_gitignored:{rel}")
        tracked_matches = _tracked_under(rel, tracked)
        if tracked_matches:
            sample = tracked_matches[0]
            errors.append(f"tracked_runtime_artifact:{sample}")

    status = _git(["status", "--short", "--untracked-files=all"])
    dirty = status.stdout.strip()
    if dirty and not args.allow_dirty:
        errors.append("git_worktree_dirty")

    if errors:
        print("release_hygiene_failed:" + ",".join(errors))
        if dirty:
            print("--- git status --short --untracked-files=all ---")
            print(dirty)
        return 1
    print("OK: release hygiene checks passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
