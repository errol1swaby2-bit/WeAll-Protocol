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
