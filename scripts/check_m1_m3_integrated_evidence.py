#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
from pathlib import Path
from typing import Callable

ROOT = Path(__file__).resolve().parents[1]
PREFIX = "artifacts/m1-m3-integrated/"
MANIFEST = PREFIX + "M1_M3_INTEGRATED_EVIDENCE_MANIFEST.json"


def run(*args: str) -> str:
    return subprocess.check_output(args, cwd=ROOT, text=True).strip()


def git_bytes(spec: str) -> bytes:
    return subprocess.check_output(["git", "show", spec], cwd=ROOT)


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def changed_paths(mode: str, commit: str) -> list[str]:
    if mode == "staged":
        raw = run("git", "diff", "--cached", "--name-status", "--diff-filter=ACMRD")
    else:
        raw = run("git", "diff-tree", "--no-commit-id", "--name-status", "-r", commit)
    paths: list[str] = []
    for line in raw.splitlines():
        if not line.strip():
            continue
        parts = line.split("\t")
        status = parts[0]
        if status[:1] not in {"A", "M"}:
            raise SystemExit(f"integrated_evidence_change_type_forbidden:{status}:{parts[-1]}")
        paths.append(parts[-1])
    return sorted(set(paths))


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--mode", choices=("staged", "commit"), required=True)
    parser.add_argument("--freeze-commit", required=True)
    parser.add_argument("--commit", default="HEAD")
    args = parser.parse_args()

    freeze = run("git", "rev-parse", f"{args.freeze_commit}^{{commit}}")
    freeze_tree = run("git", "rev-parse", f"{freeze}^{{tree}}")
    commit = ""
    if args.mode == "staged":
        if run("git", "rev-parse", "HEAD") != freeze:
            raise SystemExit("integrated_evidence_staged_head_not_freeze")
        read: Callable[[str], bytes] = lambda path: git_bytes(f":{path}")
    else:
        commit = run("git", "rev-parse", f"{args.commit}^{{commit}}")
        if run("git", "rev-parse", f"{commit}^") != freeze:
            raise SystemExit("integrated_evidence_commit_not_direct_child")
        read = lambda path: git_bytes(f"{commit}:{path}")

    paths = changed_paths(args.mode, commit)
    if not paths or MANIFEST not in paths:
        raise SystemExit("integrated_evidence_manifest_or_paths_missing")
    for path in paths:
        if not path.startswith(PREFIX):
            raise SystemExit(f"integrated_evidence_non_evidence_path:{path}")

    manifest = json.loads(read(MANIFEST).decode("utf-8"))
    if manifest.get("schema") != "weall.m1_m3.integrated_evidence.v1":
        raise SystemExit("integrated_evidence_schema_mismatch")
    if manifest.get("implementation_freeze_commit") != freeze:
        raise SystemExit("integrated_evidence_freeze_mismatch")
    if manifest.get("implementation_tree") != freeze_tree:
        raise SystemExit("integrated_evidence_tree_mismatch")
    if manifest.get("evidence_commit_parent_required") != freeze:
        raise SystemExit("integrated_evidence_parent_mismatch")
    if manifest.get("all_gates_passed") is not True:
        raise SystemExit("integrated_evidence_gates_not_passed")

    entries = manifest.get("files")
    if not isinstance(entries, list) or manifest.get("artifact_count") != len(entries):
        raise SystemExit("integrated_evidence_file_count_mismatch")
    by_path = {str(item.get("path")): item for item in entries if isinstance(item, dict)}
    expected = set(paths) - {MANIFEST}
    if set(by_path) != expected:
        raise SystemExit("integrated_evidence_path_set_mismatch")
    for path, item in by_path.items():
        data = read(path)
        if item.get("size_bytes") != len(data):
            raise SystemExit(f"integrated_evidence_size_mismatch:{path}")
        if item.get("sha256") != digest(data):
            raise SystemExit(f"integrated_evidence_hash_mismatch:{path}")

    print(f"OK: integrated M1-M3 evidence verified {len(entries)} artifacts")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
