#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

MILESTONE = "R-M3 controlled-testnet civic closure"
TRUTH_BOUNDARY = (
    "Controlled-testnet signed content, public-group, dispute/review/appeal, and "
    "no-action civic-governance finalization only; no public-beta, Mainnet, "
    "executable-governance, emergency-governance, economics, or validator-launch claim."
)
PRIVATE_MARKERS = (
    b"-----begin private key-----",
    b'"private_key"',
    b'"private_key_hex"',
    b'"recovery_phrase"',
    b'"seed_phrase"',
    b'"mnemonic"',
)


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def git(args: list[str], cwd: Path, *, required: bool = False) -> str:
    result = subprocess.run(
        ["git", *args],
        cwd=cwd,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        check=False,
    )
    if required and result.returncode != 0:
        raise SystemExit(f"m3_manifest_git_failure:{' '.join(args)}")
    return result.stdout.strip() if result.returncode == 0 else ""


def scan_private_material(path: Path) -> None:
    lower = path.read_bytes().lower()
    for marker in PRIVATE_MARKERS:
        if marker in lower:
            raise SystemExit(f"m3_evidence_contains_private_material:{path}")


def parse_results(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        if not raw_line.strip():
            continue
        parts = raw_line.split("\t", 4)
        if len(parts) not in {4, 5}:
            raise SystemExit(f"m3_results_invalid_row:{raw_line}")
        name, status, code, log_name = parts[:4]
        command = parts[4] if len(parts) == 5 else ""
        if status not in {"passed", "failed"}:
            raise SystemExit(f"m3_results_invalid_status:{name}:{status}")
        rows.append(
            {
                "gate": name,
                "status": status,
                "exit_code": int(code),
                "log": log_name,
                "command": command,
            }
        )
    if not rows:
        raise SystemExit("m3_results_empty")
    return rows


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--workspace", required=True)
    parser.add_argument("--evidence-dir", required=True)
    parser.add_argument("--results", required=True)
    parser.add_argument("--mode", default="implementation-and-evidence")
    parser.add_argument(
        "--implementation-freeze",
        default=os.environ.get("M3_IMPLEMENTATION_FREEZE_COMMIT", ""),
    )
    args = parser.parse_args()

    workspace = Path(args.workspace).resolve()
    evidence = Path(args.evidence_dir).resolve()
    results_path = Path(args.results).resolve()
    try:
        evidence.relative_to(workspace)
    except ValueError as exc:
        raise SystemExit("m3_evidence_dir_must_be_inside_workspace") from exc
    if not evidence.is_dir() or not results_path.is_file():
        raise SystemExit("m3_evidence_inputs_missing")

    freeze_raw = str(args.implementation_freeze or "").strip()
    if not freeze_raw:
        raise SystemExit("M3 implementation freeze commit is required")
    freeze = git(["rev-parse", f"{freeze_raw}^{{commit}}"], workspace, required=True)
    freeze_tree = git(["rev-parse", f"{freeze}^{{tree}}"], workspace, required=True)

    rows = parse_results(results_path)
    for row in rows:
        log_path = evidence / str(row["log"])
        if not log_path.is_file():
            raise SystemExit(f"m3_gate_log_missing:{row['gate']}:{row['log']}")
        scan_private_material(log_path)
        row["log_sha256"] = sha256(log_path)
        row["log_size_bytes"] = log_path.stat().st_size

    out = evidence / "M3_EVIDENCE_MANIFEST.json"
    files: list[dict[str, Any]] = []
    for path in sorted(evidence.rglob("*")):
        if not path.is_file() or path.resolve() == out.resolve():
            continue
        if path.is_symlink():
            raise SystemExit(f"m3_evidence_symlink_forbidden:{path}")
        scan_private_material(path)
        rel_workspace = path.relative_to(workspace).as_posix()
        files.append(
            {
                "path": rel_workspace,
                "sha256": sha256(path),
                "size_bytes": path.stat().st_size,
            }
        )
    if not files:
        raise SystemExit("m3_evidence_manifest_has_no_artifacts")

    by_path = {str(item["path"]): item for item in files}
    for row in rows:
        rel_log = (evidence / str(row["log"])).relative_to(workspace).as_posix()
        item = by_path.get(rel_log)
        if item is None or item["sha256"] != row["log_sha256"]:
            raise SystemExit(f"m3_gate_log_not_bound:{row['gate']}")
        row["log"] = rel_log

    actor_copy = evidence / "M3_ACTOR_MANIFEST.json"
    external_copy = evidence / "M3_EXTERNAL_TWO_NODE_EVIDENCE.json"
    manifest = {
        "schema_version": 2,
        "milestone": MILESTONE,
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "mode": str(args.mode),
        "implementation_freeze_commit": freeze,
        "implementation_tree": freeze_tree,
        "evidence_commit_parent_required": freeze,
        "artifact_root": evidence.relative_to(workspace).as_posix(),
        "artifact_count": len(files),
        "git_head_at_generation": git(["rev-parse", "HEAD"], workspace),
        "git_status_porcelain_at_generation": git(["status", "--porcelain"], workspace).splitlines(),
        "all_gates_passed": all(row["status"] == "passed" for row in rows),
        "gates": rows,
        "files": files,
        "actor_manifest_sha256": sha256(actor_copy) if actor_copy.is_file() else None,
        "external_two_node_evidence_sha256": sha256(external_copy)
        if external_copy.is_file()
        else None,
        "private_material_scan": "passed",
        "truth_boundary": TRUTH_BOUNDARY,
    }
    out.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(out)
    return 0 if manifest["all_gates_passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
