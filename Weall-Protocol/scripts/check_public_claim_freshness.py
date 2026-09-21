#!/usr/bin/env python3
"""Fail on high-risk claim patterns in registered current-facing documents.

The document set is data-driven through docs/CURRENT_DOCUMENT_REGISTRY.json rather
than a hard-coded path list. The registry also declares coverage_globs: any file on
those current-facing surfaces must have an exact document classification or match an
explicit classified prefix. This remains a conservative wording/freshness guard; it
does not prove repository truth or replace generated readiness authorities.
"""

from __future__ import annotations

import json
import pathlib
import re
import sys
from typing import Any

ROOT = pathlib.Path(__file__).resolve().parents[1]
REPO_ROOT = ROOT.parent
REGISTRY_PATH = ROOT / "docs/CURRENT_DOCUMENT_REGISTRY.json"
ALLOWED_CLASSIFICATIONS = {
    "CURRENT",
    "GENERATED_CURRENT",
    "NORMATIVE",
    "HISTORICAL",
    "AUDIT_EVIDENCE",
    "SUPERSEDED",
}

TPS_SCALAR = re.compile(r"\b(?:2,?271|2,?350|\d+(?:\.\d+)?)\s*TPS\b", re.IGNORECASE)
MUTABLE_COUNT = re.compile(
    r"\b\d[\d,]*\s+(?:tx types?|transactions?|requirements?|routes?|runtime states?|vectors?|source files?|blockers?)\b",
    re.IGNORECASE,
)
PYTEST_RESULT = re.compile(
    r"\b\d[\d,]*\s+passed\b(?:,\s*\d[\d,]*\s+(?:skipped|warnings?))?",
    re.IGNORECASE,
)
BLOCKER_COUNT_ASSIGNMENT = re.compile(
    r"\b(?:blocker_catalog_count|closed_in_repository_count|remaining_blocker_count|p[0-3]_open_count)\s*=\s*\d+\b",
    re.IGNORECASE,
)
ABSOLUTE_SECURITY = re.compile(
    r"\b(?:quantum[- ]safe|quantum[- ]proof|fully secure|security audited|independently audited)\b",
    re.IGNORECASE,
)
SAFE_NEGATION = re.compile(
    r"\b(?:not|no|never|unclaimed|does not|must not|remain(?:s)? required|pending)\b",
    re.IGNORECASE,
)
FUNDING_REVIEW_FRAMING = re.compile(
    r"\b(?:nlnet|first[- ]round|grant[- ]funded|grant update|funded (?:work|hardening|mainnet-readiness)|reviewer-facing|reviewer-visible|reviewer confidence|reviewer conclusion|reviewer setup|reviewer verification|reviewer evidence)\b",
    re.IGNORECASE,
)


def load_generated_truth() -> None:
    for path in (
        ROOT / "generated/v2/spec_compilation_manifest.json",
        ROOT / "generated/tx_index.json",
        ROOT / "generated/public_beta_blocker_report_v1_5.json",
    ):
        if not path.is_file():
            raise SystemExit(f"missing generated truth artifact: {path.relative_to(ROOT)}")
        json.loads(path.read_text(encoding="utf-8"))


def load_registry() -> dict[str, Any]:
    if not REGISTRY_PATH.is_file():
        raise SystemExit("missing current document registry: docs/CURRENT_DOCUMENT_REGISTRY.json")
    obj = json.loads(REGISTRY_PATH.read_text(encoding="utf-8"))
    if not isinstance(obj, dict) or obj.get("schema_version") != 1:
        raise SystemExit("invalid current document registry schema")
    docs = obj.get("documents")
    if not isinstance(docs, list) or not docs:
        raise SystemExit("current document registry has no documents")
    coverage_globs = obj.get("coverage_globs")
    if not isinstance(coverage_globs, list) or not coverage_globs:
        raise SystemExit("current document registry has no coverage_globs")
    return obj


def registered_scan_paths(registry: dict[str, Any]) -> list[pathlib.Path]:
    findings: list[str] = []
    paths: list[pathlib.Path] = []
    seen: set[str] = set()
    exact_classifications: dict[str, str] = {}

    for entry in registry["documents"]:
        if not isinstance(entry, dict):
            findings.append("registry document entry is not an object")
            continue
        raw_path = str(entry.get("path") or "").strip()
        classification = str(entry.get("classification") or "").strip()
        claim_scan = bool(entry.get("claim_scan", False))
        if not raw_path:
            findings.append("registry document entry has empty path")
            continue
        if raw_path in seen:
            findings.append(f"duplicate registry path: {raw_path}")
            continue
        seen.add(raw_path)
        if classification not in ALLOWED_CLASSIFICATIONS:
            findings.append(f"invalid classification for {raw_path}: {classification}")
            continue
        exact_classifications[raw_path] = classification
        path = REPO_ROOT / raw_path
        if not path.is_file():
            findings.append(f"missing registered document: {raw_path}")
            continue
        if claim_scan:
            if classification != "CURRENT":
                findings.append(
                    f"claim_scan=true requires CURRENT classification: {raw_path} ({classification})"
                )
                continue
            paths.append(path)

    prefix_entries: list[tuple[str, str]] = []
    for entry in registry.get("prefix_classifications", []):
        if not isinstance(entry, dict):
            findings.append("prefix classification entry is not an object")
            continue
        prefix = str(entry.get("path_prefix") or "").strip()
        classification = str(entry.get("classification") or "").strip()
        if not prefix:
            findings.append("prefix classification entry has empty path_prefix")
            continue
        if classification not in ALLOWED_CLASSIFICATIONS:
            findings.append(f"invalid prefix classification for {prefix}: {classification}")
            continue
        prefix_entries.append((prefix, classification))

    coverage_globs = registry.get("coverage_globs", [])
    for pattern in coverage_globs:
        if not isinstance(pattern, str) or not pattern.strip():
            findings.append("coverage_globs entries must be non-empty strings")
            continue
        for path in REPO_ROOT.glob(pattern):
            if not path.is_file():
                continue
            raw_path = path.relative_to(REPO_ROOT).as_posix()
            if raw_path in exact_classifications:
                continue
            if any(raw_path.startswith(prefix) for prefix, _ in prefix_entries):
                continue
            findings.append(f"unclassified covered document: {raw_path}")

    if findings:
        raise SystemExit("[claim-freshness] registry invalid\n" + "\n".join(sorted(set(findings))))
    return paths


def main() -> int:
    load_generated_truth()
    registry = load_registry()
    current_docs = registered_scan_paths(registry)
    findings: list[str] = []
    for path in current_docs:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        for lineno, line in enumerate(lines, 1):
            if TPS_SCALAR.search(line):
                findings.append(f"{path}:{lineno}: unbound TPS scalar: {line.strip()}")
            if MUTABLE_COUNT.search(line):
                findings.append(f"{path}:{lineno}: duplicated mutable count: {line.strip()}")
            if PYTEST_RESULT.search(line):
                findings.append(f"{path}:{lineno}: duplicated volatile pytest total: {line.strip()}")
            if BLOCKER_COUNT_ASSIGNMENT.search(line):
                findings.append(f"{path}:{lineno}: duplicated mutable blocker count: {line.strip()}")
            if ABSOLUTE_SECURITY.search(line) and not SAFE_NEGATION.search(line):
                findings.append(
                    f"{path}:{lineno}: unqualified absolute-security claim: {line.strip()}"
                )
            if FUNDING_REVIEW_FRAMING.search(line):
                findings.append(
                    f"{path}:{lineno}: funding/repository-review framing in current-facing prose: {line.strip()}"
                )

    if findings:
        print("[claim-freshness] FAIL")
        for finding in findings:
            print(finding)
        return 1

    print(
        f"[claim-freshness] OK: {len(current_docs)} registered CURRENT documents contain no guarded stale-claim patterns; coverage globs contain no unclassified files"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
