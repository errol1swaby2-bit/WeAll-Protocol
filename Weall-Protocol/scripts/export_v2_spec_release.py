#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
WORKSPACE_ROOT = ROOT.parent


def _run(command: list[str], *, cwd: Path = WORKSPACE_ROOT) -> subprocess.CompletedProcess[str]:
    return subprocess.run(command, cwd=cwd, text=True, capture_output=True, check=False)


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Create a commit-bound W1 release archive and detached evidence attestation."
    )
    parser.add_argument("--output-dir", default=str(WORKSPACE_ROOT / "release-artifacts"))
    parser.add_argument("--test-run-id", required=True)
    parser.add_argument("--reviewer", required=True)
    parser.add_argument("--github-run-id", default=os.getenv("GITHUB_RUN_ID", ""))
    args = parser.parse_args(argv)

    status = _run(["git", "status", "--porcelain"])
    if status.returncode != 0 or status.stdout.strip():
        print("release export requires a clean Git working tree", file=sys.stderr)
        return 1
    check = _run([sys.executable, "scripts/compile_v2_spec.py", "--check"], cwd=ROOT)
    if check.returncode != 0:
        print(check.stdout + check.stderr, file=sys.stderr)
        return check.returncode
    clean = _run([sys.executable, "scripts/check_v2_spec_clean_checkout.py"], cwd=ROOT)
    if clean.returncode != 0:
        print(clean.stdout + clean.stderr, file=sys.stderr)
        return clean.returncode

    commit = _run(["git", "rev-parse", "HEAD"]).stdout.strip()
    provenance = json.loads((ROOT / "specs/v2/source/provenance.json").read_text())
    implementation_commit = str(provenance.get("repository", {}).get("implementation_commit") or "")
    if len(implementation_commit) != 40:
        print("provenance does not contain a finalized implementation commit", file=sys.stderr)
        return 1
    if not _run(["git", "merge-base", "--is-ancestor", implementation_commit, commit]).returncode == 0:
        print("finalized implementation commit is not an ancestor of release HEAD", file=sys.stderr)
        return 1

    output_dir = Path(args.output_dir).resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    archive = output_dir / f"WeAll-W1-{commit[:12]}.zip"
    result = _run(["git", "archive", "--format=zip", "-o", str(archive), commit])
    if result.returncode != 0:
        print(result.stdout + result.stderr, file=sys.stderr)
        return result.returncode

    spec_manifest = ROOT / "generated/v2/spec_compilation_manifest.json"
    closure_manifest = ROOT / "generated/v2/w1_closure_validation_manifest.json"
    timestamp = datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    attestation = {
        "schema": "weall.v2.w1_release_export_attestation",
        "release_commit": commit,
        "implementation_commit": implementation_commit,
        "created_at": timestamp,
        "archive": {"filename": archive.name, "sha256": _sha256(archive), "bytes": archive.stat().st_size},
        "spec_compilation_manifest_sha256": _sha256(spec_manifest),
        "w1_closure_validation_manifest_sha256": _sha256(closure_manifest),
        "test_run_id": args.test_run_id,
        "reviewer": args.reviewer,
        "github_run_id": args.github_run_id or None,
        "compiler_check": check.stdout.strip(),
        "clean_checkout_check": clean.stdout.strip(),
        "authority_effect": "none; public testnet and Mainnet remain disabled",
    }
    attestation_path = output_dir / f"WeAll-W1-{commit[:12]}-attestation.json"
    attestation_path.write_text(json.dumps(attestation, indent=2, sort_keys=False) + "\n")
    print(f"wrote {archive}")
    print(f"wrote {attestation_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
