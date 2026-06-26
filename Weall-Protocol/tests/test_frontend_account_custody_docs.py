from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
WEB = ROOT.parent / "web"


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def test_account_custody_doc_exists_and_requires_recovery_verification() -> None:
    doc = _read(ROOT / "docs" / "ACCOUNT_CUSTODY_AND_RECOVERY.md")

    assert "Account custody and recovery" in doc
    assert "download" in doc.lower()
    assert "verify" in doc.lower()
    assert "easy sign-in" in doc.lower()
    assert "does not replace" in doc.lower()


def test_frontend_account_custody_source_gate_is_tracked() -> None:
    script = _read(WEB / "scripts" / "test_account_custody_source.mjs")
    reviewer = _read(ROOT / "scripts" / "reviewer_production_readiness_gate.sh")

    assert "recoveryVerified" in script
    assert "verifyRecoveryKeyFileForAccount" in script
    assert "test_account_custody_source.mjs" in reviewer
