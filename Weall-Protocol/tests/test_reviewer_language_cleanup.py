from __future__ import annotations

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


REVIEWER_FACING_PATHS = [
    "docs/TRUTH_BOUNDARY.md",
    "docs/REVIEWER_MILESTONE_GUIDE.md",
    "docs/REVIEWER_EVIDENCE_INDEX.md",
    "docs/KNOWN_LIMITATIONS.md",
    "docs/PRODUCTION_ORIENTED_REHEARSAL_GAP_AUDIT.md",
    "scripts/check_reviewer_truth_boundaries.py",
    "scripts/verify_node_operator_onboarding_bundle.py",
]


def _read(rel: str) -> str:
    return (ROOT / rel).read_text(encoding="utf-8")


def test_no_reviewert_typo_in_reviewer_facing_docs_or_scripts() -> None:
    hits: list[str] = []

    for rel in REVIEWER_FACING_PATHS:
        for lineno, line in enumerate(_read(rel).splitlines(), 1):
            if "reviewert" in line.lower():
                hits.append(f"{rel}:{lineno}:{line}")

    assert hits == []


def test_truth_boundary_checker_uses_reviewer_language() -> None:
    text = _read("scripts/check_reviewer_truth_boundaries.py")

    assert "reviewer-facing docs" in text
    assert "reviewer submission" in text
    assert "reviewer readiness claims" in text
    assert "reviewert" not in text.lower()


def test_bundle_verifier_help_uses_reviewer_language() -> None:
    text = _read("scripts/verify_node_operator_onboarding_bundle.py")

    assert "reviewer/external-observer path" in text
    assert "reviewer/external observer onboarding" in text
    assert "reviewert" not in text.lower()


def test_truth_boundary_checker_still_passes() -> None:
    result = subprocess.run(
        [sys.executable, "scripts/check_reviewer_truth_boundaries.py"],
        cwd=ROOT,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )

    assert result.returncode == 0, result.stdout + result.stderr
    assert "[truth-boundary] OK" in result.stdout
    assert "reviewer readiness claims" in result.stdout
    assert "reviewert" not in (result.stdout + result.stderr).lower()



def test_reviewer_readmes_do_not_use_unbounded_readiness_claims() -> None:
    paths = [
        ROOT.parent / "README.md",
        ROOT.parent / "RELEASE_CHECKLIST.md",
        ROOT / "README.md",
        ROOT / "docs" / "reviewer" / "CURRENT_READINESS_STATEMENT.md",
        ROOT / "docs" / "reviewer" / "EVIDENCE_INDEX.md",
        ROOT / "docs" / "reviewer" / "PUBLIC_BETA_BLOCKER_STATUS.md",
        ROOT / "docs" / "testnet" / "FINAL_PUBLIC_OBSERVER_CONTROLLED_TESTNET_GO_GATE.md",
        ROOT / "docs" / "testnet" / "PUBLIC_OBSERVER_QUICKSTART.md",
        ROOT / "docs" / "testnet" / "TESTNET_LAUNCH_CHECKLIST.md",
        ROOT / "docs" / "PRODUCTION_POSTURE.md",
        ROOT / "docs" / "PROTOCOL_VERSIONING_STRATEGY.md",
    ]
    unsafe_regexes = [
        "weall is public beta ready",
        "weall is mainnet ready",
        "weall is production ready",
        "public validators are safe",
        "automatic upgrades are ready",
        "live economics are ready",
        "legally approved",
        "decentralized storage ready",
        "public storage market ready",
    ]
    findings: list[str] = []
    for path in paths:
        text = path.read_text(encoding="utf-8").lower()
        for phrase in unsafe_regexes:
            if phrase in text:
                findings.append(f"{path}: {phrase}")
    assert findings == []
