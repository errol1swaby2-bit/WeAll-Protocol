from __future__ import annotations

from pathlib import Path


def test_devnet_email_tier1_harness_uses_provider_neutral_attestation_path() -> None:
    root = Path(__file__).resolve().parents[1]
    helper = (root / "scripts" / "devnet_tx.py").read_text(encoding="utf-8")
    submit = (root / "scripts" / "devnet_submit_email_attestation.sh").read_text(encoding="utf-8")

    combined = helper + "\n" + submit
    assert "POH_EMAIL_ATTESTATION_SUBMIT" in combined
    assert "/v1/poh/email/begin" in helper
    assert "/v1/poh/email/complete" in helper
    assert "/v1/poh/email/tx/receipt-submit" not in combined
    assert "POH_EMAIL_RECEIPT_SUBMIT" not in combined
    assert "WEALL_EMAIL_RELAY" not in combined
    assert "operator_email_receipts" not in combined
    assert "worker_account_id" not in combined
    assert "worker_pubkey" not in combined
