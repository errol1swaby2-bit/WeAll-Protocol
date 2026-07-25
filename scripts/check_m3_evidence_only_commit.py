#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
from pathlib import Path
from typing import Any, Callable

ROOT = Path(__file__).resolve().parents[1]
ARTIFACT_ROOT = "artifacts/m3-closure"
MANIFEST_PATH = f"{ARTIFACT_ROOT}/M3_EVIDENCE_MANIFEST.json"
REQUIRED_GATES = {
    "dependency preflight",
    "M3 requirement traceability",
    "governance execution vectors current",
    "M3 runtime regression suite",
    "M3 persistence replay and convergence",
    "helper serial equivalence and fallback",
    "full backend suite",
    "frontend public social source",
    "frontend account profile source",
    "frontend first-run source",
    "frontend governance source",
    "frontend dispute source",
    "frontend typecheck",
    "frontend production build",
    "M3 real-stack actor journey",
    "external two-node equal-root evidence",
}
PRIVATE_MARKERS = (
    b"-----begin private key-----",
    b'"private_key"',
    b'"private_key_hex"',
    b'"recovery_phrase"',
    b'"seed_phrase"',
    b'"mnemonic"',
)


def run(*args: str) -> str:
    return subprocess.check_output(args, cwd=ROOT, text=True).strip()


def git_bytes(spec: str) -> bytes:
    return subprocess.check_output(["git", "show", spec], cwd=ROOT)


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def parse_json(data: bytes, label: str) -> dict[str, Any]:
    try:
        value = json.loads(data.decode("utf-8"))
    except Exception as exc:
        raise SystemExit(f"m3_evidence_invalid_json:{label}") from exc
    if not isinstance(value, dict):
        raise SystemExit(f"m3_evidence_json_not_object:{label}")
    return value


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
            raise SystemExit(f"m3_evidence_change_type_forbidden:{status}:{parts[-1]}")
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
    commit = run("git", "rev-parse", f"{args.commit}^{{commit}}") if args.mode == "commit" else ""
    if args.mode == "staged":
        if run("git", "rev-parse", "HEAD") != freeze:
            raise SystemExit("m3_evidence_staged_head_not_freeze")
    elif run("git", "rev-parse", f"{commit}^") != freeze:
        raise SystemExit("m3_evidence_commit_not_direct_child")

    paths = changed_paths(args.mode, commit)
    if not paths or MANIFEST_PATH not in paths:
        raise SystemExit("m3_evidence_manifest_or_paths_missing")
    for path in paths:
        if not path.startswith(f"{ARTIFACT_ROOT}/"):
            raise SystemExit(f"m3_evidence_non_evidence_path:{path}")

    def read(path: str) -> bytes:
        spec = f":{path}" if args.mode == "staged" else f"{commit}:{path}"
        try:
            return git_bytes(spec)
        except subprocess.CalledProcessError as exc:
            raise SystemExit(f"m3_evidence_blob_missing:{path}") from exc

    manifest_bytes = read(MANIFEST_PATH)
    if any(marker in manifest_bytes.lower() for marker in PRIVATE_MARKERS):
        raise SystemExit("m3_evidence_private_material:manifest")
    manifest = parse_json(manifest_bytes, MANIFEST_PATH)
    if manifest.get("schema_version") != 2:
        raise SystemExit("m3_evidence_manifest_schema_mismatch")
    if manifest.get("implementation_freeze_commit") != freeze:
        raise SystemExit("m3_evidence_manifest_freeze_mismatch")
    if manifest.get("implementation_tree") != freeze_tree:
        raise SystemExit("m3_evidence_manifest_tree_mismatch")
    if manifest.get("evidence_commit_parent_required") != freeze:
        raise SystemExit("m3_evidence_manifest_parent_mismatch")
    if manifest.get("artifact_root") != ARTIFACT_ROOT:
        raise SystemExit("m3_evidence_manifest_root_mismatch")
    if manifest.get("all_gates_passed") is not True:
        raise SystemExit("m3_evidence_manifest_has_failed_gate")
    if manifest.get("private_material_scan") != "passed":
        raise SystemExit("m3_evidence_private_scan_missing")

    files = manifest.get("files")
    if not isinstance(files, list) or manifest.get("artifact_count") != len(files):
        raise SystemExit("m3_evidence_manifest_file_count_mismatch")
    entries: dict[str, dict[str, Any]] = {}
    for item in files:
        if not isinstance(item, dict) or set(item) != {"path", "sha256", "size_bytes"}:
            raise SystemExit("m3_evidence_manifest_file_entry_invalid")
        path = str(item.get("path") or "")
        if not path.startswith(f"{ARTIFACT_ROOT}/") or path == MANIFEST_PATH or path in entries:
            raise SystemExit(f"m3_evidence_manifest_bad_path:{path}")
        entries[path] = item
    committed = set(paths) - {MANIFEST_PATH}
    if set(entries) != committed:
        raise SystemExit(
            "m3_evidence_manifest_path_set_mismatch:"
            + json.dumps(
                {
                    "missing_from_manifest": sorted(committed - set(entries)),
                    "not_in_commit": sorted(set(entries) - committed),
                },
                sort_keys=True,
            )
        )

    blobs: dict[str, bytes] = {}
    for path, item in entries.items():
        data = read(path)
        blobs[path] = data
        if item.get("size_bytes") != len(data) or item.get("sha256") != digest(data):
            raise SystemExit(f"m3_evidence_file_binding_mismatch:{path}")
        if any(marker in data.lower() for marker in PRIVATE_MARKERS):
            raise SystemExit(f"m3_evidence_private_material:{path}")

    gates = manifest.get("gates")
    if not isinstance(gates, list):
        raise SystemExit("m3_evidence_gates_missing")
    by_gate: dict[str, dict[str, Any]] = {}
    for gate in gates:
        if not isinstance(gate, dict):
            raise SystemExit("m3_evidence_gate_invalid")
        name = str(gate.get("gate") or "")
        if not name or name in by_gate:
            raise SystemExit(f"m3_evidence_gate_duplicate_or_blank:{name}")
        if gate.get("status") != "passed" or int(gate.get("exit_code") or -1) != 0:
            raise SystemExit(f"m3_evidence_gate_not_passed:{name}")
        log = str(gate.get("log") or "")
        if log not in entries:
            raise SystemExit(f"m3_evidence_gate_log_missing:{name}:{log}")
        if gate.get("log_sha256") != entries[log]["sha256"]:
            raise SystemExit(f"m3_evidence_gate_log_hash_mismatch:{name}")
        by_gate[name] = gate
    if set(by_gate) != REQUIRED_GATES:
        raise SystemExit(
            "m3_evidence_gate_set_mismatch:"
            + json.dumps(
                {
                    "missing": sorted(REQUIRED_GATES - set(by_gate)),
                    "unexpected": sorted(set(by_gate) - REQUIRED_GATES),
                },
                sort_keys=True,
            )
        )

    for required in (
        f"{ARTIFACT_ROOT}/M3_ACTOR_MANIFEST.json",
        f"{ARTIFACT_ROOT}/M3_EXTERNAL_TWO_NODE_EVIDENCE.json",
        f"{ARTIFACT_ROOT}/gate-results.tsv",
    ):
        if required not in entries:
            raise SystemExit(f"m3_evidence_required_artifact_missing:{required}")

    print(
        f"OK: M3 evidence-only commit verified {len(entries)} artifacts and "
        f"{len(by_gate)} mandatory gates"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
