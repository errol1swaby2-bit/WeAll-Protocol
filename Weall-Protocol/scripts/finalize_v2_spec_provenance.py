#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PROVENANCE = ROOT / "specs" / "v2" / "source" / "provenance.json"


def _git(*args: str) -> str:
    result = subprocess.run(
        ["git", *args],
        cwd=ROOT.parent,
        text=True,
        capture_output=True,
        check=False,
    )
    if result.returncode != 0:
        raise RuntimeError(result.stdout + result.stderr)
    return result.stdout.strip()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Bind the non-circular W1 closure provenance to the clean implementation "
            "commit. Run after committing the technical closure patch; commit the "
            "result as a separate evidence-only finalization commit."
        )
    )
    parser.add_argument("--test-run-id", required=True)
    parser.add_argument("--reviewer", required=True)
    parser.add_argument("--github-run-id", default="")
    args = parser.parse_args(argv)

    status = _git("status", "--porcelain")
    if status:
        print("refusing to bind provenance from a dirty working tree", file=sys.stderr)
        return 1
    commit = _git("rev-parse", "HEAD")
    timestamp = datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")

    payload = json.loads(PROVENANCE.read_text(encoding="utf-8"))
    repository = payload.setdefault("repository", {})
    repository["implementation_commit"] = commit
    repository["implementation_commit_scope"] = "w1_technical_closure_commit"
    repository["closure_finalization"] = {
        "binding_model": "non_circular_two_commit_evidence_binding",
        "implementation_commit": commit,
        "verification_timestamp": timestamp,
        "test_run_id": args.test_run_id,
        "reviewer": args.reviewer,
        "github_run_id": args.github_run_id or None,
        "authority_effect": "none; public testnet and Mainnet remain disabled",
        "next_step": "commit these provenance and derivative changes as an evidence-only finalization commit",
    }
    PROVENANCE.write_text(
        json.dumps(payload, indent=2, sort_keys=False) + "\n",
        encoding="utf-8",
    )

    result = subprocess.run(
        [sys.executable, "scripts/compile_v2_spec.py"],
        cwd=ROOT,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        return result.returncode
    print(f"bound W1 implementation provenance to {commit}")
    print("commit the resulting evidence-only changes, then run export_v2_spec_release.py")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
