#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
import tempfile
from collections import Counter
from pathlib import Path

DiagnosticKey = tuple[str, str, str]


def _git(repo_root: Path, *args: str, check: bool = True) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["git", *args],
        cwd=repo_root,
        text=True,
        capture_output=True,
        check=check,
    )


def _collect_changed_python_paths(repo_root: Path, base_ref: str) -> list[str]:
    tracked = _git(
        repo_root,
        "diff",
        "--name-only",
        "--diff-filter=ACMRTUXB",
        base_ref,
        "--",
    ).stdout.splitlines()

    untracked = _git(
        repo_root,
        "ls-files",
        "--others",
        "--exclude-standard",
    ).stdout.splitlines()

    paths: set[str] = set()

    for raw_path in [*tracked, *untracked]:
        path = raw_path.strip().replace("\\", "/")

        if not path.startswith("Weall-Protocol/"):
            continue

        backend_path = path.removeprefix("Weall-Protocol/")

        if not backend_path.endswith(".py"):
            continue

        if not backend_path.startswith(("src/", "tests/", "scripts/")):
            continue

        paths.add(backend_path)

    return sorted(paths)


def _run_ruff(backend_root: Path, paths: list[str]) -> list[dict[str, object]]:
    if not paths:
        return []

    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "ruff",
            "check",
            "--output-format=json",
            *paths,
        ],
        cwd=backend_root,
        text=True,
        capture_output=True,
        check=False,
    )

    if result.returncode not in {0, 1}:
        if result.stdout:
            print(result.stdout, file=sys.stderr)
        if result.stderr:
            print(result.stderr, file=sys.stderr)

        raise RuntimeError(
            f"Ruff execution failed with unexpected return code "
            f"{result.returncode} in {backend_root}"
        )

    try:
        payload = json.loads(result.stdout or "[]")
    except json.JSONDecodeError as exc:
        raise RuntimeError(
            f"Ruff returned invalid JSON in {backend_root}: {exc}"
        ) from exc

    if not isinstance(payload, list):
        raise RuntimeError("Ruff JSON output must be a list")

    diagnostics: list[dict[str, object]] = []

    for item in payload:
        if isinstance(item, dict):
            diagnostics.append(item)

    return diagnostics


def _relative_filename(
    diagnostic: dict[str, object],
    backend_root: Path,
) -> str:
    raw_filename = str(diagnostic.get("filename") or "")
    path = Path(raw_filename)

    if not path.is_absolute():
        path = backend_root / path

    try:
        return path.resolve().relative_to(backend_root.resolve()).as_posix()
    except ValueError:
        return path.as_posix()


def _diagnostic_key(
    diagnostic: dict[str, object],
    backend_root: Path,
) -> DiagnosticKey:
    return (
        _relative_filename(diagnostic, backend_root),
        str(diagnostic.get("code") or ""),
        str(diagnostic.get("message") or ""),
    )


def _location_value(
    diagnostic: dict[str, object],
    field: str,
) -> int:
    location = diagnostic.get("location")

    if not isinstance(location, dict):
        return 0

    value = location.get(field)

    try:
        return int(value)
    except (TypeError, ValueError):
        return 0


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Reject Ruff diagnostics added beyond an explicit Git baseline "
            "without hiding historical repository lint debt."
        )
    )
    parser.add_argument(
        "--repo-root",
        required=True,
        help="Path to the outer WeAll repository root.",
    )
    parser.add_argument(
        "--base-ref",
        required=True,
        help="Retired implementation commit or another explicit Git baseline.",
    )
    parser.add_argument(
        "--json-out",
        help="Optional path for the machine-readable comparison report.",
    )
    args = parser.parse_args()

    repo_root = Path(args.repo_root).resolve()
    backend_root = repo_root / "Weall-Protocol"

    if not backend_root.is_dir():
        print(
            f"ERROR: backend directory does not exist: {backend_root}",
            file=sys.stderr,
        )
        return 2

    try:
        base_commit = _git(
            repo_root,
            "rev-parse",
            "--verify",
            f"{args.base_ref}^{{commit}}",
        ).stdout.strip()
    except subprocess.CalledProcessError:
        print(
            f"ERROR: invalid Ruff baseline ref: {args.base_ref}",
            file=sys.stderr,
        )
        return 2

    changed_paths = _collect_changed_python_paths(
        repo_root,
        base_commit,
    )

    temporary_root = Path(
        tempfile.mkdtemp(prefix="weall-ruff-baseline-")
    )
    baseline_worktree = temporary_root / "worktree"
    baseline_attached = False

    try:
        add_result = _git(
            repo_root,
            "worktree",
            "add",
            "--detach",
            str(baseline_worktree),
            base_commit,
            check=False,
        )

        if add_result.returncode != 0:
            if add_result.stdout:
                print(add_result.stdout, file=sys.stderr)
            if add_result.stderr:
                print(add_result.stderr, file=sys.stderr)

            print(
                "ERROR: could not create detached Ruff baseline worktree",
                file=sys.stderr,
            )
            return 2

        baseline_attached = True
        baseline_backend = baseline_worktree / "Weall-Protocol"

        current_diagnostics = _run_ruff(
            backend_root,
            changed_paths,
        )

        baseline_paths = [
            path
            for path in changed_paths
            if (baseline_backend / path).is_file()
        ]

        baseline_diagnostics = _run_ruff(
            baseline_backend,
            baseline_paths,
        )

        current_counts: Counter[DiagnosticKey] = Counter(
            _diagnostic_key(item, backend_root)
            for item in current_diagnostics
        )

        baseline_counts: Counter[DiagnosticKey] = Counter(
            _diagnostic_key(item, baseline_backend)
            for item in baseline_diagnostics
        )

        added_counts = current_counts - baseline_counts
        added_diagnostics: list[dict[str, object]] = []

        current_by_key: dict[
            DiagnosticKey,
            list[dict[str, object]],
        ] = {}

        for diagnostic in current_diagnostics:
            key = _diagnostic_key(
                diagnostic,
                backend_root,
            )
            current_by_key.setdefault(key, []).append(diagnostic)

        for key in sorted(added_counts):
            surplus = added_counts[key]
            candidates = current_by_key.get(key, [])

            for diagnostic in candidates[:surplus]:
                added_diagnostics.append(
                    {
                        "path": key[0],
                        "code": key[1],
                        "message": key[2],
                        "row": _location_value(
                            diagnostic,
                            "row",
                        ),
                        "column": _location_value(
                            diagnostic,
                            "column",
                        ),
                    }
                )

        summary = {
            "schema": "weall.ruff_regression_report.v1",
            "base_ref": args.base_ref,
            "base_commit": base_commit,
            "changed_python_file_count": len(changed_paths),
            "changed_python_files": changed_paths,
            "current_diagnostic_count": len(current_diagnostics),
            "baseline_diagnostic_count": len(baseline_diagnostics),
            "added_diagnostic_count": sum(added_counts.values()),
            "added_diagnostics": added_diagnostics,
            "status": (
                "passed"
                if not added_diagnostics
                else "failed"
            ),
            "claim_boundary": (
                "This gate rejects newly added Ruff diagnostics in changed "
                "Python files. It does not claim that the full repository is "
                "Ruff-clean."
            ),
        }

        rendered = json.dumps(
            summary,
            sort_keys=True,
            indent=2,
        ) + "\n"

        print(rendered, end="")

        if args.json_out:
            output_path = Path(args.json_out)
            output_path.parent.mkdir(
                parents=True,
                exist_ok=True,
            )
            output_path.write_text(
                rendered,
                encoding="utf-8",
            )

        return 0 if not added_diagnostics else 1

    except RuntimeError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2

    finally:
        if baseline_attached:
            _git(
                repo_root,
                "worktree",
                "remove",
                "--force",
                str(baseline_worktree),
                check=False,
            )
            _git(
                repo_root,
                "worktree",
                "prune",
                check=False,
            )

        shutil.rmtree(
            temporary_root,
            ignore_errors=True,
        )


if __name__ == "__main__":
    raise SystemExit(main())
