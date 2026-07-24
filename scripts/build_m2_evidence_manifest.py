#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import os
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
    MILESTONE,
    PRIVATE_MARKERS,
    REQUIRED_PREFIXES,
    STATE_SUMMARY_PATHS,
    SUCCESS_MARKERS,
    TRANSCRIPT_PATHS,
    TRUTH_BOUNDARY,
)

DEFAULT_ARTIFACT_ROOT = ROOT / ARTIFACT_ROOT


def run(*args: str) -> str:
    return subprocess.check_output(args, cwd=ROOT, text=True).strip()


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def scan_private_material(path: Path) -> None:
    data = path.read_bytes().lower()
    if any(marker.lower() in data for marker in PRIVATE_MARKERS):
        raise SystemExit(f"m2_evidence_contains_private_material:{path.relative_to(ROOT)}")


def state_summary(path: Path, *, label: str) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        raise SystemExit(f"m2_state_summary_invalid_json:{label}:{path}") from exc
    if not isinstance(value, dict) or value.get("equal") is not True:
        raise SystemExit(f"m2_state_summary_not_equal:{label}:{path}")
    final = value.get("final")
    if not isinstance(final, dict):
        raise SystemExit(f"m2_state_summary_final_missing:{label}:{path}")
    for field in ("chain_id", "height", "tip_hash", "state_root", "tx_index_hash", "protocol_profile_hash"):
        if final.get(field) in (None, ""):
            raise SystemExit(f"m2_state_summary_field_missing:{label}:{field}")
    return final


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--freeze-commit", default=os.environ.get("M2_IMPLEMENTATION_FREEZE_COMMIT", ""))
    parser.add_argument("--artifact-root", default=str(DEFAULT_ARTIFACT_ROOT))
    parser.add_argument("--out", default="")
    args = parser.parse_args()

    freeze = str(args.freeze_commit).strip()
    if not freeze:
        raise SystemExit("M2 implementation freeze commit is required")
    resolved = run("git", "rev-parse", f"{freeze}^{{commit}}")
    tree = run("git", "rev-parse", f"{resolved}^{{tree}}")
    artifact_root = Path(args.artifact_root).expanduser().resolve()
    if not artifact_root.is_dir():
        raise SystemExit(f"m2_artifact_root_missing:{artifact_root}")
    try:
        artifact_root.relative_to(ROOT)
    except ValueError as exc:
        raise SystemExit("m2_artifact_root_must_be_inside_repository") from exc
    out = Path(args.out).expanduser().resolve() if args.out else artifact_root / "M2_EVIDENCE_MANIFEST.json"

    files: list[dict[str, Any]] = []
    by_path: dict[str, dict[str, Any]] = {}
    for path in sorted(p for p in artifact_root.rglob("*") if p.is_file()):
        if path.resolve() == out:
            continue
        if path.is_symlink():
            raise SystemExit(f"m2_evidence_symlink_forbidden:{path.relative_to(ROOT)}")
        scan_private_material(path)
        rel = str(path.relative_to(ROOT))
        item = {"path": rel, "sha256": sha256(path), "size_bytes": path.stat().st_size}
        files.append(item)
        by_path[rel] = item
    if not files:
        raise SystemExit("m2_evidence_manifest_has_no_artifacts")

    paths = list(by_path)
    missing = [prefix for prefix in REQUIRED_PREFIXES if not any(path.startswith(prefix) for path in paths)]
    if missing:
        raise SystemExit(f"m2_evidence_required_prefix_missing:{missing}")

    for command in COMMAND_LEDGER:
        evidence = str(command["evidence"])
        if evidence not in by_path:
            raise SystemExit(f"m2_evidence_command_artifact_missing:{command['id']}:{evidence}")

    for rule in SUCCESS_MARKERS:
        rel = rule["path"]
        item = by_path.get(rel)
        if item is None:
            raise SystemExit(f"m2_evidence_success_artifact_missing:{rel}")
        text = (ROOT / rel).read_text(encoding="utf-8", errors="replace")
        if "contains" in rule and rule["contains"] not in text:
            raise SystemExit(f"m2_evidence_success_marker_missing:{rel}")
        if "regex" in rule and not re.search(rule["regex"], text):
            raise SystemExit(f"m2_evidence_success_regex_missing:{rel}")

    final_state_roots: dict[str, Any] = {}
    for label, rel in STATE_SUMMARY_PATHS.items():
        path = ROOT / rel
        if rel not in by_path:
            raise SystemExit(f"m2_state_summary_missing:{label}:{rel}")
        final_state_roots[label] = state_summary(path, label=label)

    transcript_hashes: dict[str, str] = {}
    for rel in TRANSCRIPT_PATHS:
        item = by_path.get(rel)
        if item is None:
            raise SystemExit(f"m2_transcript_missing:{rel}")
        transcript_hashes[rel] = str(item["sha256"])

    manifest = {
        "schema_version": 2,
        "milestone": MILESTONE,
        "implementation_freeze_commit": resolved,
        "implementation_tree": tree,
        "evidence_commit_parent_required": resolved,
        "artifact_root": str(artifact_root.relative_to(ROOT)),
        "artifact_count": len(files),
        "commands": [dict(item) for item in COMMAND_LEDGER],
        "transcript_hashes": transcript_hashes,
        "final_state_roots": final_state_roots,
        "files": files,
        "truth_boundary": TRUTH_BOUNDARY,
    }
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(manifest, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    print(out)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
