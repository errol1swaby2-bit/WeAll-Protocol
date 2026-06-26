from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_clean_clone_tester_boot_rehearsal_doc_exists() -> None:
    doc = (ROOT / "docs" / "CLEAN_CLONE_TESTER_BOOT_REHEARSAL.md").read_text(encoding="utf-8")

    assert "Clean Clone Tester Boot Rehearsal" in doc
    assert "requirements.lock" in doc
    assert "requirements-dev.lock" in doc
    assert "reviewer_production_readiness_gate.sh" in doc
    assert "weall_genesis_rehearsal.sh" in doc
    assert "weall_tester_node.sh" in doc
    assert "--api-port 8001" in doc
    assert "--frontend-port 5174" in doc
    assert "BFT/helper/block production: disabled" in doc


def test_clean_clone_tester_boot_doc_preserves_truth_boundary() -> None:
    doc = (ROOT / "docs" / "CLEAN_CLONE_TESTER_BOOT_REHEARSAL.md").read_text(encoding="utf-8")

    assert "does not prove" in doc
    assert "public multi-validator BFT readiness" in doc
    assert "public HTTPS external observer readiness" in doc
    assert "WEALL_ALLOW_LAN_GENESIS_API=1" in doc
    assert "private key must never be printed" in doc.lower()
