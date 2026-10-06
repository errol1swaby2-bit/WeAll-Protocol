from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
APP = ROOT / "Weall-Protocol"
START_HERE = APP / "docs" / "reviewer" / "START_HERE.md"


def test_a19_f004_root_readme_links_canonical_reviewer_front_door() -> None:
    root_readme = (ROOT / "README.md").read_text(encoding="utf-8")

    assert "Weall-Protocol/docs/reviewer/START_HERE.md" in root_readme
    assert "Verification entry point" in root_readme


def test_a19_f004_front_door_distinguishes_non_equivalent_review_paths() -> None:
    text = START_HERE.read_text(encoding="utf-8")

    required_sections = (
        "Exact reviewer-readiness verification",
        "Historyless source-archive verification",
        "Fresh-clone smoke",
        "External observer / onboarding node",
        "Local developer/demo flows",
        "Decision table",
    )
    for section in required_sections:
        assert section in text

    # Preserve the two key non-equivalence boundaries found by A19.
    assert "full-history Git clone" in text
    assert "not equivalent to the full-history Reviewer Readiness gate" in text
    assert "exact 40-hex commit under review" in text
    assert "skips frontend verification" in text
    assert "not substitutes for Reviewer Readiness" in text


def test_a19_f004_front_door_names_current_truth_sources() -> None:
    text = START_HERE.read_text(encoding="utf-8")

    assert "generated/current_verified_claims.json" in text
    assert "docs/CURRENT_VERIFIED_CLAIMS.md" in text
    assert "audit-metadata/p1-revalidation-after-p0-20261005/MATRIX.json" in text
    assert "docs/reviewer/EVIDENCE_INDEX.md" in text
