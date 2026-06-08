#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

RELEASE_ARTIFACTS = [
    Path("generated/api_contract_map_v1_5.json"),
    Path("generated/launch_disabled_matrix_v1_5.json"),
    Path("generated/v15_implementation_gap_register.json"),
]
GITIGNORE_EXCEPTIONS = [f"!{path.as_posix()}" for path in RELEASE_ARTIFACTS]


def _load_json(rel: Path) -> dict:
    path = ROOT / rel
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        raise SystemExit(f"invalid json artifact {rel}: {exc}") from exc
    if not isinstance(value, dict):
        raise SystemExit(f"json artifact root must be an object: {rel}")
    return value


def _check_gitignore() -> list[str]:
    errors: list[str] = []
    text = (ROOT / ".gitignore").read_text(encoding="utf-8")
    for line in GITIGNORE_EXCEPTIONS:
        if line not in text.splitlines():
            errors.append(f"missing .gitignore exception: {line}")
    return errors


def _check_api_contract() -> list[str]:
    errors: list[str] = []
    result = subprocess.run(
        [sys.executable, "scripts/gen_api_contract_map.py", "--check"],
        cwd=ROOT,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if result.returncode != 0:
        errors.append((result.stdout + result.stderr).strip() or "api contract map check failed")
    payload = _load_json(Path("generated/api_contract_map_v1_5.json"))
    if payload.get("schema") != "weall.api_contract_map.v1_5":
        errors.append("api contract map schema mismatch")
    routes = payload.get("routes")
    if not isinstance(routes, list) or len(routes) < 120:
        errors.append("api contract map route list missing or unexpectedly small")
    return errors


def _check_launch_matrix() -> list[str]:
    errors: list[str] = []
    from weall.runtime.launch_matrix import launch_matrix_payload

    artifact = _load_json(Path("generated/launch_disabled_matrix_v1_5.json"))
    runtime = launch_matrix_payload()
    if artifact != runtime:
        errors.append("launch_disabled_matrix_v1_5.json is stale; regenerate from weall.runtime.launch_matrix.launch_matrix_payload()")
    return errors


def _check_gap_register() -> list[str]:
    errors: list[str] = []
    payload = _load_json(Path("generated/v15_implementation_gap_register.json"))
    if payload.get("schema") != "weall.v15_implementation_gap_register":
        errors.append("v15 implementation gap register schema mismatch")
    for key in ("resolved_since_prior_evidence_map", "remaining_p0_p1_gaps"):
        if not isinstance(payload.get(key), list) or not payload.get(key):
            errors.append(f"v15 gap register missing non-empty {key}")
    return errors


def _check_git_tracked() -> list[str]:
    errors: list[str] = []
    if not (ROOT / ".git").exists() and not (ROOT.parent / ".git").exists():
        return errors
    for rel in RELEASE_ARTIFACTS:
        result = subprocess.run(
            ["git", "ls-files", "--error-unmatch", rel.as_posix()],
            cwd=ROOT,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )
        if result.returncode != 0:
            errors.append(f"release artifact is not tracked/staged in git index: {rel.as_posix()}")
    return errors


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Check v1.5 public-readiness generated artifacts are release-safe and fresh.")
    parser.add_argument("--require-git-tracked", action="store_true", help="also require generated artifacts to already be tracked/staged in git")
    args = parser.parse_args(argv)

    errors: list[str] = []
    for rel in RELEASE_ARTIFACTS:
        if not (ROOT / rel).is_file():
            errors.append(f"missing release artifact: {rel.as_posix()}")
    errors.extend(_check_gitignore())
    if not errors:
        errors.extend(_check_api_contract())
        errors.extend(_check_launch_matrix())
        errors.extend(_check_gap_register())
    if args.require_git_tracked:
        errors.extend(_check_git_tracked())
    if errors:
        for err in errors:
            print(f"[v15-artifacts] FAIL: {err}", file=sys.stderr)
        return 1
    print("[v15-artifacts] OK: v1.5 public-readiness artifacts are present, fresh, and release-safe")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
