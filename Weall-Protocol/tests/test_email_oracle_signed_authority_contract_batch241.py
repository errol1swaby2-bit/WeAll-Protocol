from __future__ import annotations

from pathlib import Path


def test_weall_owned_email_oracle_service_exists_batch241() -> None:
    root = Path(__file__).resolve().parents[1]
    src = (root / "src" / "weall" / "poh" / "email_verification.py").read_text(encoding="utf-8")
    assert "WeAll-owned PoH email verification oracle" in src
    assert "def begin(" in src
    assert "def complete(" in src
