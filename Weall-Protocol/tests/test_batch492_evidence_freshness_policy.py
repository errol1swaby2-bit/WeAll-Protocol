from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _read(rel: str) -> str:
    return (ROOT / rel).read_text(encoding="utf-8")


def test_batch492_evidence_index_requires_current_commit_bound_transcripts() -> None:
    text = _read("docs/REVIEWER_EVIDENCE_INDEX.md")

    assert "## Evidence freshness policy" in text
    assert "exact Git commit being submitted" in text
    assert "fresh output from the exact Git commit" in text
    assert "Do not reuse stale audit-export output" in text
    assert "Do not present full pytest" in text
    assert "the transcript is included" in text


def test_batch492_evidence_index_keeps_required_truth_boundaries() -> None:
    text = _read("docs/REVIEWER_EVIDENCE_INDEX.md")

    assert "public mainnet" in text
    assert "public multi-validator BFT" in text
    assert "live economics" in text
    assert "local precondition only" in text
    assert "remote signed observer onboarding" in text
    assert "local block evidence only" in text
    assert "controlled LAN/reviewer rehearsal only" in text


def test_batch492_evidence_index_lists_fresh_commands() -> None:
    text = _read("docs/REVIEWER_EVIDENCE_INDEX.md")

    required_commands = [
        "git rev-parse --abbrev-ref HEAD",
        "python3 -B -S scripts/check_tx_canon_artifacts.py",
        "bash scripts/secret_guard.sh",
        "bash scripts/verify_release_tree.sh",
        "bash scripts/verify_release_dependencies.sh",
        "bash scripts/reviewer_production_readiness_gate.sh",
        "PYTHONPATH=src pytest",
        "npm run typecheck",
        "bash scripts/local_observer_readiness_gate.sh",
        "bash scripts/external_observer_authority_lock_gate.sh",
        "bash scripts/reviewer_lan_genesis_rehearsal.sh",
        "bash scripts/reviewer_observer_rehearsal.sh",
        "PYTHONPATH=src python3 scripts/production_block_production_rehearsal_gate.py",
    ]

    for command in required_commands:
        assert command in text


def test_batch492_stale_audit_export_transcripts_removed() -> None:
    text = _read("docs/REVIEWER_EVIDENCE_INDEX.md")

    stale_phrases = [
        "Captured command results from latest audit export",
        "2026-05-29 audit export environment",
        "WARN: not a git work tree",
        "93 passed in 20.31s",
        "66 passed in 17.84s",
        "ModuleNotFoundError: No module named 'nacl'",
        "A plain full pytest run in the audit sandbox did not complete",
        "Do not present full pytest as passed unless this command has passed",
    ]

    for phrase in stale_phrases:
        assert phrase not in text
