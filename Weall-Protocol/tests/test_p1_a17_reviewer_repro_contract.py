from __future__ import annotations

import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
APP = ROOT / "Weall-Protocol"


def test_a17_f001_reviewer_contract_explicitly_distinguishes_history_and_archive() -> None:
    text = (APP / "docs" / "reviewer" / "START_HERE.md").read_text(encoding="utf-8")

    assert "full-history Git clone" in text
    assert "GitHub source tarball or `git archive` is not equivalent" in text
    assert "Historyless source-archive verification" in text
    assert "cannot reproduce the full history-backed reviewer procedure" in text
    assert "not equivalent to the full-history Reviewer Readiness gate" in text


def test_a17_f001_history_restore_preflights_exact_commit_objects() -> None:
    script = (ROOT / "scripts" / "restore_m2_m3_evidence_from_git.sh").read_text(encoding="utf-8")

    required_defaults = (
        "017cadc8d7825036b23fe0bc07156ca763eb52fc",
        "1d0d36c71fc63ea7383f604e7ea3306898a647fd",
        "4ca0e13e1e4838b8816e977e33f8dd82fae3b7c5",
        "72b9122e1d67b216cc8d678f921951a5a52175ad",
        "04e55d8b84313d134b255f768dd6575e6cc64e42",
    )
    for commit in required_defaults:
        assert commit in script

    assert 'git -C "${ROOT}" cat-file -e "${commit}^{commit}"' in script
    assert "required historical commit is unavailable locally: ${commit}" in script
    assert "Fetch the repository history before retrying." in script


def test_a17_f001_full_history_preflight_verifies_current_clone() -> None:
    proc = subprocess.run(
        ["bash", "scripts/restore_m2_m3_evidence_from_git.sh", "--verify-only"],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
        timeout=45,
    )

    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "historical M2 and M3 evidence pairs verified" in proc.stdout


def test_a17_f001_archive_reproducible_v2_gate_executes() -> None:
    proc = subprocess.run(
        ["python", "scripts/check_v2_spec_clean_checkout.py"],
        cwd=APP,
        text=True,
        capture_output=True,
        check=False,
        timeout=45,
    )

    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "clean Git archive reproduces all WeAll v2 specification derivatives" in proc.stdout
