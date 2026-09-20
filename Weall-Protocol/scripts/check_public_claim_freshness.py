#!/usr/bin/env python3
"""Fail on reviewer-facing claim patterns that are known to become stale.

This guard is intentionally narrow. It does not prove repository truth; it prevents
reintroduction of a few high-risk classes of unbound claims into current-facing docs.
Historical/audit documents are allowed to retain explicitly historical measurements.
"""

from __future__ import annotations

import json
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
CURRENT_DOCS = [
    ROOT / "README.md",
    ROOT.parent / "README.md",
    ROOT / "docs/reviewer/CURRENT_READINESS_STATEMENT.md",
    ROOT / "docs/reviewer/CURRENT_TESTNET_READINESS_STATEMENT.md",
]

TPS_SCALAR = re.compile(r"\b(?:2,?271|2,?350|\d+(?:\.\d+)?)\s*TPS\b", re.IGNORECASE)
MUTABLE_COUNT = re.compile(
    r"\b\d[\d,]*\s+(?:tx types?|transactions?|requirements?|routes?|runtime states?|vectors?|source files?|blockers?)\b",
    re.IGNORECASE,
)
ABSOLUTE_SECURITY = re.compile(
    r"\b(?:quantum[- ]safe|quantum[- ]proof|fully secure|security audited|independently audited)\b",
    re.IGNORECASE,
)
SAFE_NEGATION = re.compile(
    r"\b(?:not|no|never|unclaimed|does not|must not|remain(?:s)? required|pending)\b", re.IGNORECASE
)


def load_generated_truth() -> None:
    manifest = ROOT / "generated/v2/spec_compilation_manifest.json"
    tx_index = ROOT / "generated/tx_index.json"
    blockers = ROOT / "generated/public_beta_blocker_report_v1_5.json"
    for path in (manifest, tx_index, blockers):
        if not path.is_file():
            raise SystemExit(f"missing generated truth artifact: {path.relative_to(ROOT)}")
        json.loads(path.read_text(encoding="utf-8"))


def main() -> int:
    load_generated_truth()
    findings: list[str] = []
    for path in CURRENT_DOCS:
        if not path.is_file():
            findings.append(f"missing current-facing document: {path}")
            continue
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        for lineno, line in enumerate(lines, 1):
            if TPS_SCALAR.search(line):
                findings.append(f"{path}:{lineno}: unbound TPS scalar: {line.strip()}")
            if MUTABLE_COUNT.search(line):
                findings.append(f"{path}:{lineno}: duplicated mutable count: {line.strip()}")

    if findings:
        print("[claim-freshness] FAIL")
        for finding in findings:
            print(finding)
        return 1

    print(
        "[claim-freshness] OK: no unbound TPS scalars or duplicated mutable counts in current-facing docs"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
