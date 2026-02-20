# tests/test_no_plaintext_email_on_chain.py
from __future__ import annotations

from pathlib import Path


def test_no_plaintext_email_key_in_onchain_payload_construction() -> None:
    """Regression guard: never include plaintext 'email' in chain-persisted tx payloads.

    We allow 'email' usage only in off-chain verification/oracle calls.
    This test scans backend source for JSON/dict literals that contain the key
    "email" (as a string literal), which is the most common way plaintext email
    accidentally leaks into tx payloads.

    If you intentionally add other legitimate off-chain uses, extend the allowlist.
    """

    repo = Path(__file__).resolve().parents[1]
    src = repo / "src" / "weall"

    allowed_paths = {
        # Off-chain verifier/oracle communication
        (src / "poh" / "email_verification.py").resolve(),
    }

    offenders: list[str] = []

    for p in src.rglob("*.py"):
        rp = p.resolve()
        text = p.read_text(encoding="utf-8", errors="ignore")

        if '"email"' not in text and "'email'" not in text:
            continue

        # Allowlist only for verified off-chain modules.
        if rp in allowed_paths:
            continue

        # Any occurrence is suspicious enough to fail-closed.
        offenders.append(str(p.relative_to(repo)))

    assert not offenders, (
        "Plaintext email key literal found outside off-chain verifier; "
        "this risks persisting PII on-chain via tx payloads. Offenders: "
        + ", ".join(sorted(offenders))
    )
