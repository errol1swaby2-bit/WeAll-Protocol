#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

cd "${GITHUB_WORKSPACE}"

# Remove one-shot infrastructure before source-sensitive derivative generation.
git rm -f .github/workflows/claim-surface-registry-hardening-once.yml scripts/claim-surface-registry-hardening-once.sh

python - <<'PY'
from __future__ import annotations

import json
from pathlib import Path

repo = Path.cwd()
backend = repo / "Weall-Protocol"

registry = {
    "schema_version": 1,
    "description": "Repository document classification and claim-scan registry. CURRENT entries with claim_scan=true are enforced by scripts/check_public_claim_freshness.py.",
    "classifications": [
        "CURRENT",
        "GENERATED_CURRENT",
        "NORMATIVE",
        "HISTORICAL",
        "AUDIT_EVIDENCE",
        "SUPERSEDED"
    ],
    "documents": [
        {"path": "README.md", "classification": "CURRENT", "claim_scan": True},
        {"path": "Weall-Protocol/README.md", "classification": "CURRENT", "claim_scan": True},
        {"path": "Weall-Protocol/RELEASE_CHECKLIST.md", "classification": "CURRENT", "claim_scan": True},
        {"path": "Weall-Protocol/docs/PUBLIC_BETA_BLOCKERS.md", "classification": "CURRENT", "claim_scan": True},
        {"path": "Weall-Protocol/docs/PROFESSIONALIZATION_BACKLOG.md", "classification": "CURRENT", "claim_scan": True},
        {"path": "Weall-Protocol/docs/reviewer/CURRENT_READINESS_STATEMENT.md", "classification": "CURRENT", "claim_scan": True},
        {"path": "Weall-Protocol/docs/reviewer/CURRENT_TESTNET_READINESS_STATEMENT.md", "classification": "CURRENT", "claim_scan": True},
        {"path": "Weall-Protocol/docs/reviewer/CURRENT_STATE_UPDATE_2026_08.md", "classification": "CURRENT", "claim_scan": True},
        {"path": "Weall-Protocol/docs/reviewer/DIRECT_MESSAGE_TRANSACTION_QUARANTINE.md", "classification": "CURRENT", "claim_scan": True},
        {"path": "Weall-Protocol/docs/testnet/FINAL_PUBLIC_OBSERVER_CONTROLLED_TESTNET_GO_GATE.md", "classification": "CURRENT", "claim_scan": True},
        {"path": "Weall-Protocol/docs/CURRENT_VERIFIED_CLAIMS.md", "classification": "GENERATED_CURRENT", "claim_scan": False},
        {"path": "Weall-Protocol/generated/current_verified_claims.json", "classification": "GENERATED_CURRENT", "claim_scan": False},
        {"path": "Weall-Protocol/generated/public_beta_blocker_report_v1_5.json", "classification": "GENERATED_CURRENT", "claim_scan": False},
        {"path": "Weall-Protocol/generated/release_evidence_manifest_v1_5.json", "classification": "GENERATED_CURRENT", "claim_scan": False}
    ],
    "prefix_classifications": [
        {"path_prefix": "audit-metadata/", "classification": "AUDIT_EVIDENCE"},
        {"path_prefix": "Weall-Protocol/docs/audits/", "classification": "AUDIT_EVIDENCE"},
        {"path_prefix": "Weall-Protocol/generated/v2/", "classification": "GENERATED_CURRENT"}
    ]
}
(backend / "docs/CURRENT_DOCUMENT_REGISTRY.json").write_text(
    json.dumps(registry, indent=2, sort_keys=True) + "\n", encoding="utf-8"
)

checker = r'''#!/usr/bin/env python3
"""Fail on high-risk claim patterns in registered current-facing documents.

The document set is data-driven through docs/CURRENT_DOCUMENT_REGISTRY.json rather
than a hard-coded path list. This remains a conservative wording/freshness guard;
it does not prove repository truth or replace generated readiness authorities.
Historical, audit-evidence, normative, superseded, and generated-current artifacts
are classified separately and are not scanned unless the registry explicitly opts
them into current-prose claim scanning.
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
    return obj


def registered_scan_paths(registry: dict[str, Any]) -> list[pathlib.Path]:
    findings: list[str] = []
    paths: list[pathlib.Path] = []
    seen: set[str] = set()
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
    if findings:
        raise SystemExit("[claim-freshness] registry invalid\n" + "\n".join(findings))
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
        f"[claim-freshness] OK: {len(current_docs)} registered CURRENT documents contain no guarded stale-claim patterns"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
'''
(backend / "scripts/check_public_claim_freshness.py").write_text(checker, encoding="utf-8")

# Current release checklist: remove review-process framing and mutable generated counts.
path = backend / "RELEASE_CHECKLIST.md"
text = path.read_text(encoding="utf-8")
repls = {
    "# WeAll Release / Reviewer Checklist": "# WeAll Release Verification Checklist",
    "This checklist is for reviewer-facing documentation and bounded rehearsal preparation against the current generated readiness artifacts.": "This checklist is for current release documentation and bounded rehearsal preparation against the generated readiness authorities.",
    "GO for local review only": "GO for local verification only",
    "local/reviewer evidence": "local verification evidence",
    "If README or reviewer docs changed in the reviewed commit": "If README or registered current-facing docs changed in the commit",
    "## Frontend reviewer checks": "## Frontend verification checks",
    "local observer/reviewer rehearsal remains available": "local observer verification rehearsal remains available",
    "Refresh reviewer documentation truth boundaries": "Refresh release documentation truth boundaries",
}
for old, new in repls.items():
    text = text.replace(old, new)
text = text.replace(
    "Current tx canon checkpoint: **236 tx types, version 1.25.0**.",
    "Current transaction-canon count and version are authoritative in `generated/tx_index.json`; this checklist does not duplicate those mutable values."
)
text = text.replace(
    "| Public beta blocker status | `Weall-Protocol/docs/reviewer/PUBLIC_BETA_BLOCKER_STATUS.md` | 15 blockers visible; 7 closed in repo; 8 open. |",
    "| Public beta blocker status | `Weall-Protocol/docs/reviewer/PUBLIC_BETA_BLOCKER_STATUS.md` | Generated blocker totals and dispositions remain authoritative; open blockers remain visible. |"
)
text = text.replace(
    "| Generated blocker report | `Weall-Protocol/generated/public_beta_blocker_report_v1_5.json` | `public_beta_ready=false`; `blocker_catalog_count=15`; `closed_in_repository_count=7`; `remaining_blocker_count=8`; `p0_open_count=4`; `p1_open_count=4`. |",
    "| Generated blocker report | `Weall-Protocol/generated/public_beta_blocker_report_v1_5.json` | `public_beta_ready=false`; mutable blocker totals and severity counts are read from this artifact rather than duplicated here. |"
)
old_block = """- Public beta readiness remains false.\n- The blocker catalog remains 15 entries.\n- 7 entries are closed in repository.\n- 8 entries remain open as external evidence or mainnet-hardening gates.\n- P0 open count remains 4.\n- P1 open count remains 4.\n- Local scripts and generated artifacts can prove repository consistency, but they cannot self-certify missing external operator, counsel, storage, replay, helper, observer, upgrade-execution, or cryptographic-review evidence."""
new_block = """- Public beta readiness remains false.\n- Current blocker totals, closed/open dispositions, and severity counts are authoritative only in `generated/public_beta_blocker_report_v1_5.json`.\n- Local scripts and generated artifacts can prove repository consistency, but they cannot self-certify missing external operator, counsel, storage, replay, helper, observer, upgrade-execution, or cryptographic-review evidence."""
text = text.replace(old_block, new_block)
path.write_text(text, encoding="utf-8")

# Finish neutralizing active direct-message scope wording while retaining protocol semantics.
path = backend / "docs/reviewer/DIRECT_MESSAGE_TRANSACTION_QUARANTINE.md"
text = path.read_text(encoding="utf-8")
text = text.replace("the NLnet/public-testnet claim", "the current public-testnet scope")
text = text.replace("part of the NLnet/public-testnet claim", "part of the current public-testnet scope")
text = text.replace("reviewer-visible UI", "current UI")
text = text.replace("## Reviewer interpretation", "## Verification interpretation")
path.write_text(text, encoding="utf-8")

# Keep the current backlog actionable while removing repository-review-process framing.
path = backend / "docs/PROFESSIONALIZATION_BACKLOG.md"
text = path.read_text(encoding="utf-8")
for old, new in {
    "reviewer-surface hygiene pass": "verification-surface hygiene pass",
    "## P0 — reviewer-facing cleanup before broad external review": "## P0 — verification-surface cleanup before broad external validation",
    "reviewer-facing test references": "verification-facing test references",
    "external reviewer notes": "external validation notes",
    "reviewer-history breakage": "verification-history breakage",
    "operator/reviewer": "operator/verification",
}.items():
    text = text.replace(old, new)
path.write_text(text, encoding="utf-8")

# Remove mutable generated values from the current go-gate prose.
path = backend / "docs/testnet/FINAL_PUBLIC_OBSERVER_CONTROLLED_TESTNET_GO_GATE.md"
text = path.read_text(encoding="utf-8")
text = text.replace(
    "Current tx canon checkpoint: **236 tx types, version 1.25.0**.",
    "Current transaction-canon count and version are authoritative in `generated/tx_index.json`."
)
for line in [
    "- `blocker_catalog_count=15`;\n",
    "- `closed_in_repository_count=7`;\n",
    "- `remaining_blocker_count=8`;\n",
    "- `remaining_external_evidence_required_count=8`;\n",
    "- `p0_open_count=4`;\n",
    "- `p1_open_count=4`;\n",
]:
    text = text.replace(line, "")
text = text.replace(
    "- allowed claim limited to the pre-public-testnet hardening statement; controlled-testnet mechanism completion is NO-GO;\n",
    "- allowed claim limited to the pre-public-testnet hardening statement; controlled-testnet mechanism completion is NO-GO;\n- mutable blocker totals and severity counts are authoritative in `generated/public_beta_blocker_report_v1_5.json` and are not duplicated here;\n"
)
path.write_text(text, encoding="utf-8")

# Regression coverage for the registry contract.
test = r'''from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
REPO_ROOT = ROOT.parent


def test_current_document_registry_is_unique_and_resolvable() -> None:
    registry = json.loads((ROOT / "docs/CURRENT_DOCUMENT_REGISTRY.json").read_text(encoding="utf-8"))
    assert registry["schema_version"] == 1
    docs = registry["documents"]
    paths = [entry["path"] for entry in docs]
    assert len(paths) == len(set(paths))
    assert any(entry["classification"] == "CURRENT" for entry in docs)
    for entry in docs:
        assert (REPO_ROOT / entry["path"]).is_file()
        if entry.get("claim_scan"):
            assert entry["classification"] == "CURRENT"


def test_claim_freshness_checker_is_registry_driven() -> None:
    text = (ROOT / "scripts/check_public_claim_freshness.py").read_text(encoding="utf-8")
    assert "CURRENT_DOCUMENT_REGISTRY.json" in text
    assert "CURRENT_DOCS =" not in text
    assert "claim_scan=true requires CURRENT classification" in text
'''
(backend / "tests/test_current_document_registry.py").write_text(test, encoding="utf-8")
PY

cd Weall-Protocol
ruff format scripts/check_public_claim_freshness.py tests/test_current_document_registry.py
ruff check scripts/check_public_claim_freshness.py tests/test_current_document_registry.py

python scripts/gen_public_only_protocol_audit_v1_5.py
PYTHONPATH=src:scripts python scripts/gen_public_beta_blocker_report_v1_5.py
PYTHONPATH=src python scripts/gen_release_evidence_manifest_v1_5.py
PYTHONPATH=src python scripts/gen_current_verified_claims.py
PYTHONPATH=src python scripts/compile_v2_spec.py

python scripts/check_generated.py
PYTHONPATH=src python scripts/compile_v2_spec.py --check
python scripts/check_v2_spec_clean_checkout.py
PYTHONDONTWRITEBYTECODE=1 python scripts/check_v15_public_readiness_artifacts.py
python scripts/check_public_claim_freshness.py
python scripts/gen_current_verified_claims.py --check
pytest -q tests/test_current_document_registry.py tests/test_release_docs_truth_sync.py tests/test_reviewer_language_cleanup.py

git diff --check

git add -A
git status --short

git config user.name "github-actions[bot]"
git config user.email "41898282+github-actions[bot]@users.noreply.github.com"
git commit -m "Harden current claim surface registry"
git push origin HEAD:claim-surface-registry-hardening
