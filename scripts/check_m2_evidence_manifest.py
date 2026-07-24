#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(Path(__file__).resolve().parent))

from m2_evidence_contract import (  # noqa: E402
    ARTIFACT_ROOT,
    COMMAND_LEDGER,
    FILE_ENTRY_KEYS,
    MANIFEST_TOP_LEVEL_KEYS,
    MILESTONE,
    PRIVATE_MARKERS,
    REQUIRED_PREFIXES,
    STATE_SUMMARY_PATHS,
    SUCCESS_MARKERS,
    TRANSCRIPT_PATHS,
    TRUTH_BOUNDARY,
)

MANIFEST = f"{ARTIFACT_ROOT}/M2_EVIDENCE_MANIFEST.json"


def run(*args: str) -> str:
    return subprocess.check_output(args, cwd=ROOT, text=True).strip()


def git_bytes(spec: str) -> bytes:
    return subprocess.check_output(["git", "show", spec], cwd=ROOT)


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def changed_paths(*, mode: str, commit: str) -> list[str]:
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
            raise SystemExit(f"m2_evidence_change_type_forbidden:{status}:{parts[-1]}")
        path = parts[-1]
        paths.append(path)
    return sorted(set(paths))


def reader(*, mode: str, commit: str):
    def read(path: str) -> bytes:
        spec = f":{path}" if mode == "staged" else f"{commit}:{path}"
        try:
            return git_bytes(spec)
        except subprocess.CalledProcessError as exc:
            raise SystemExit(f"m2_evidence_blob_missing:{path}") from exc

    return read


def parse_json(data: bytes, *, label: str) -> dict[str, Any]:
    try:
        value = json.loads(data.decode("utf-8"))
    except Exception as exc:
        raise SystemExit(f"m2_evidence_invalid_json:{label}") from exc
    if not isinstance(value, dict):
        raise SystemExit(f"m2_evidence_json_not_object:{label}")
    return value


def validate_state_summary(value: dict[str, Any], *, label: str) -> dict[str, Any]:
    if value.get("equal") is not True:
        raise SystemExit(f"m2_state_summary_not_equal:{label}")
    final = value.get("final")
    if not isinstance(final, dict):
        raise SystemExit(f"m2_state_summary_final_missing:{label}")
    for field in ("chain_id", "height", "tip_hash", "state_root", "tx_index_hash", "protocol_profile_hash"):
        if final.get(field) in (None, ""):
            raise SystemExit(f"m2_state_summary_field_missing:{label}:{field}")
    return final


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
            raise SystemExit("m2_evidence_staged_head_not_freeze")
    else:
        if run("git", "rev-parse", f"{commit}^") != freeze:
            raise SystemExit("m2_evidence_commit_not_direct_child")

    paths = changed_paths(mode=args.mode, commit=commit)
    if not paths:
        raise SystemExit("m2_evidence_no_paths")
    for path in paths:
        if not path.startswith("artifacts/m2-closure/"):
            raise SystemExit(f"m2_evidence_non_evidence_path:{path}")
    if MANIFEST not in paths:
        raise SystemExit("m2_evidence_manifest_missing")

    read = reader(mode=args.mode, commit=commit)
    manifest_bytes = read(MANIFEST)
    lower_manifest = manifest_bytes.lower()
    if any(marker.lower() in lower_manifest for marker in PRIVATE_MARKERS):
        raise SystemExit("m2_evidence_private_material:manifest")
    manifest = parse_json(manifest_bytes, label=MANIFEST)
    if set(manifest) != MANIFEST_TOP_LEVEL_KEYS:
        raise SystemExit("m2_evidence_manifest_top_level_keys_mismatch")
    if manifest.get("schema_version") != 2:
        raise SystemExit("m2_evidence_manifest_schema_mismatch")
    if manifest.get("implementation_freeze_commit") != freeze:
        raise SystemExit("m2_evidence_manifest_freeze_commit_mismatch")
    if manifest.get("implementation_tree") != freeze_tree:
        raise SystemExit("m2_evidence_manifest_tree_mismatch")
    if manifest.get("evidence_commit_parent_required") != freeze:
        raise SystemExit("m2_evidence_manifest_parent_mismatch")
    if manifest.get("milestone") != MILESTONE:
        raise SystemExit("m2_evidence_manifest_milestone_mismatch")
    if manifest.get("artifact_root") != ARTIFACT_ROOT:
        raise SystemExit("m2_evidence_manifest_artifact_root_mismatch")
    if manifest.get("truth_boundary") != TRUTH_BOUNDARY:
        raise SystemExit("m2_evidence_manifest_truth_boundary_mismatch")

    files = manifest.get("files")
    if not isinstance(files, list) or not files:
        raise SystemExit("m2_evidence_manifest_empty")
    if manifest.get("artifact_count") != len(files):
        raise SystemExit("m2_evidence_manifest_artifact_count_mismatch")

    entries: dict[str, dict[str, Any]] = {}
    for item in files:
        if not isinstance(item, dict):
            raise SystemExit("m2_evidence_manifest_file_entry_not_object")
        if set(item) != FILE_ENTRY_KEYS:
            raise SystemExit("m2_evidence_manifest_file_entry_keys_mismatch")
        path = str(item.get("path") or "")
        if not path.startswith("artifacts/m2-closure/") or path == MANIFEST:
            raise SystemExit(f"m2_evidence_manifest_bad_path:{path}")
        if path in entries:
            raise SystemExit(f"m2_evidence_manifest_duplicate_path:{path}")
        entries[path] = item

    committed_artifacts = set(paths) - {MANIFEST}
    if set(entries) != committed_artifacts:
        raise SystemExit(
            "m2_evidence_manifest_path_set_mismatch:" + json.dumps(
                {
                    "missing_from_manifest": sorted(committed_artifacts - set(entries)),
                    "not_in_commit": sorted(set(entries) - committed_artifacts),
                },
                sort_keys=True,
            )
        )

    for prefix in REQUIRED_PREFIXES:
        if not any(path.startswith(prefix) for path in entries):
            raise SystemExit(f"m2_evidence_required_prefix_missing:{prefix}")

    lowered_markers = tuple(marker.lower() for marker in PRIVATE_MARKERS)
    blobs: dict[str, bytes] = {}
    for path, item in entries.items():
        data = read(path)
        blobs[path] = data
        if item.get("size_bytes") != len(data):
            raise SystemExit(f"m2_evidence_size_mismatch:{path}")
        if item.get("sha256") != digest(data):
            raise SystemExit(f"m2_evidence_sha256_mismatch:{path}")
        lower = data.lower()
        if any(marker in lower for marker in lowered_markers):
            raise SystemExit(f"m2_evidence_private_material:{path}")

    expected_commands = [dict(item) for item in COMMAND_LEDGER]
    if manifest.get("commands") != expected_commands:
        raise SystemExit("m2_evidence_command_ledger_mismatch")
    for item in expected_commands:
        evidence = str(item["evidence"])
        if evidence not in entries:
            raise SystemExit(f"m2_evidence_command_artifact_missing:{item['id']}:{evidence}")

    for rule in SUCCESS_MARKERS:
        path = rule["path"]
        data = blobs.get(path)
        if data is None:
            raise SystemExit(f"m2_evidence_success_artifact_missing:{path}")
        text = data.decode("utf-8", errors="replace")
        if "contains" in rule and rule["contains"] not in text:
            raise SystemExit(f"m2_evidence_success_marker_missing:{path}")
        if "regex" in rule and not re.search(rule["regex"], text):
            raise SystemExit(f"m2_evidence_success_regex_missing:{path}")

    expected_roots: dict[str, Any] = {}
    for label, path in STATE_SUMMARY_PATHS.items():
        value = parse_json(blobs.get(path) or read(path), label=path)
        expected_roots[label] = validate_state_summary(value, label=label)
    if manifest.get("final_state_roots") != expected_roots:
        raise SystemExit("m2_evidence_final_state_roots_mismatch")

    expected_transcripts = {path: digest(blobs[path]) for path in TRANSCRIPT_PATHS}
    if manifest.get("transcript_hashes") != expected_transcripts:
        raise SystemExit("m2_evidence_transcript_hashes_mismatch")

    print(
        f"OK: M2 evidence manifest verified {len(entries)} artifacts, "
        f"{len(expected_commands)} commands, and {len(expected_roots)} final state-root summaries"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
