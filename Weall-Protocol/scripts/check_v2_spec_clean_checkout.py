#!/usr/bin/env python3
from __future__ import annotations

import argparse
import os
import subprocess
import sys
import tarfile
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
WORKSPACE_ROOT = ROOT.parent


def _run(command: list[str], *, cwd: Path, env: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        command,
        cwd=cwd,
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Verify that a clean Git archive reproduces committed WeAll v2 derivatives."
    )
    parser.add_argument(
        "--skip-if-no-git",
        action="store_true",
        help="return success when the working tree is not backed by Git",
    )
    args = parser.parse_args(argv)

    probe = _run(["git", "rev-parse", "--show-toplevel"], cwd=WORKSPACE_ROOT)
    if probe.returncode != 0:
        if args.skip_if_no_git:
            print("SKIP: clean-checkout verification requires a Git working tree")
            return 0
        print(probe.stdout + probe.stderr, file=sys.stderr)
        return 1

    git_root = Path(probe.stdout.strip()).resolve()
    if git_root != WORKSPACE_ROOT.resolve():
        print(
            f"unexpected Git root: expected {WORKSPACE_ROOT.resolve()} found {git_root}",
            file=sys.stderr,
        )
        return 1

    with tempfile.TemporaryDirectory(prefix="weall-v2-clean-") as raw_temp:
        temp_root = Path(raw_temp)
        archive_path = temp_root / "source.tar"
        archive = _run(
            ["git", "archive", "--format=tar", "HEAD", "-o", str(archive_path)],
            cwd=git_root,
        )
        if archive.returncode != 0:
            print(archive.stdout + archive.stderr, file=sys.stderr)
            return 1
        with tarfile.open(archive_path, mode="r") as tar:
            tar.extractall(temp_root / "checkout", filter="data")

        checkout_root = temp_root / "checkout"
        protocol_root = checkout_root / "Weall-Protocol"
        env = dict(os.environ)
        env["PYTHONPATH"] = "src"
        check = _run(
            [sys.executable, "scripts/compile_v2_spec.py", "--check"],
            cwd=protocol_root,
            env=env,
        )
        if check.returncode != 0:
            print(check.stdout + check.stderr, file=sys.stderr)
            return 1
        print(check.stdout.strip())
        print("OK: clean Git archive reproduces all WeAll v2 specification derivatives")
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
