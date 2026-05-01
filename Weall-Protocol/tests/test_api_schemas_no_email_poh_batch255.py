from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_public_api_schema_module_no_longer_exports_legacy_email_poh_requests() -> None:
    text = (ROOT / "src/weall/api/schemas.py").read_text(encoding="utf-8")
    assert "PohEmailStartRequest" not in text
    assert "PohEmailConfirmRequest" not in text
    assert "Email address" not in text
    assert "Verification code" not in text
