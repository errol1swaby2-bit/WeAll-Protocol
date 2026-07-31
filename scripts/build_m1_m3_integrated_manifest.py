#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
MANIFEST_NAME = "M1_M3_INTEGRATED_EVIDENCE_MANIFEST.json"


def git(*args: str) -> str:
    return subprocess.check_output(["git", *args], cwd=ROOT, text=True).strip()


def digest(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def read_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise SystemExit(f"json_not_object:{path}")
    return value


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--artifact-root", default="artifacts/m1-m3-integrated")
    parser.add_argument("--freeze-commit", required=True)
    parser.add_argument("--mode", choices=("source-only", "full"), required=True)
    args = parser.parse_args()

    artifact_root = (ROOT / args.artifact_root).resolve()
    if not str(artifact_root).startswith(str(ROOT.resolve())):
        raise SystemExit("artifact_root_outside_repository")
    freeze = git("rev-parse", f"{args.freeze_commit}^{{commit}}")
    tree = git("rev-parse", f"{freeze}^{{tree}}")
    if git("rev-parse", "HEAD") != freeze:
        raise SystemExit("integrated_manifest_head_not_freeze")

    manifest_path = artifact_root / MANIFEST_NAME
    files: list[dict[str, Any]] = []
    for path in sorted(p for p in artifact_root.rglob("*") if p.is_file()):
        if path == manifest_path:
            continue
        rel = path.relative_to(ROOT).as_posix()
        files.append({"path": rel, "size_bytes": path.stat().st_size, "sha256": digest(path)})

    results_path = artifact_root / "gate-results.tsv"
    results = []
    if results_path.is_file():
        for line in results_path.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            parts = line.split("\t", 4)
            if len(parts) >= 4:
                results.append(
                    {
                        "gate": parts[0],
                        "status": parts[1],
                        "returncode": int(parts[2]),
                        "evidence": parts[3],
                    }
                )
    all_passed = bool(results) and all(item["status"] == "passed" for item in results)

    profile_path = ROOT / "Weall-Protocol/configs/consensus_profiles/weall-m1-m3-production-v1.json"
    profile = read_json(profile_path)
    nested: dict[str, Any] = {}
    for label, rel in (
        ("m2", "m2/M2_EVIDENCE_MANIFEST.json"),
        ("m3", "m3/M3_EVIDENCE_MANIFEST.json"),
    ):
        path = artifact_root / rel
        if path.is_file():
            nested[label] = {
                "path": path.relative_to(ROOT).as_posix(),
                "sha256": digest(path),
            }

    value = {
        "schema": "weall.m1_m3.integrated_evidence.v1",
        "milestone": "Spec-M1+M2+R-M3-current-head-roll-forward",
        "mode": args.mode,
        "implementation_freeze_commit": freeze,
        "implementation_tree": tree,
        "evidence_commit_parent_required": freeze,
        "artifact_root": artifact_root.relative_to(ROOT).as_posix(),
        "artifact_count": len(files),
        "all_gates_passed": all_passed,
        "gate_count": len(results),
        "gate_results": results,
        "consensus_profile_manifest": {
            "path": profile_path.relative_to(ROOT).as_posix(),
            "manifest_hash": profile.get("manifest_hash"),
            "sha256": digest(profile_path),
        },
        "nested_evidence_manifests": nested,
        "truth_boundary": (
            "Current-head cumulative closure of the Spec-M1 specification-control plane, "
            "M2 controlled-testnet account/PoH lifecycle, and R-M3 controlled-testnet signed "
            "civic/governance flows at the recorded implementation freeze."
        ),
        "exclusions": [
            "R-M1 real remote signed observer onboarding unless separately evidenced",
            "public multi-validator BFT authorization",
            "live economics and production validator admission",
            "production executable constitutional, treasury, emergency, or upgrade governance",
            "Mainnet authorization",
            "independent external security review",
        ],
        "files": files,
    }
    manifest_path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    if not all_passed:
        raise SystemExit("integrated_manifest_contains_failed_or_missing_gates")
    print(f"OK: wrote {manifest_path} with {len(files)} bound artifacts")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
