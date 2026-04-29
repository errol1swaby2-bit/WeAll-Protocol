from __future__ import annotations

import json
from pathlib import Path

from weall.runtime.tx_schema import TX_PAYLOADS


def test_legacy_poh_email_receipt_submit_is_removed_from_runtime_and_canon() -> None:
    root = Path(__file__).resolve().parents[1]
    assert "POH_EMAIL_RECEIPT_SUBMIT" not in TX_PAYLOADS
    assert not (root / "src" / "weall" / "poh" / "operator_email_receipts.py").exists()

    for rel in (
        "specs/tx_canon/tx_canon.yaml",
        "generated/tx_index.json",
        "generated/tx_contract_map.json",
        "generated/helper_contract_map.json",
        "src/weall/runtime/apply/poh.py",
        "src/weall/runtime/tx_contracts.py",
        "src/weall/runtime/tx_conflicts.py",
        "src/weall/runtime/poh/eligibility.py",
    ):
        assert "POH_EMAIL_RECEIPT_SUBMIT" not in (root / rel).read_text(encoding="utf-8")


def test_generated_tx_index_count_after_receipt_removal() -> None:
    root = Path(__file__).resolve().parents[1]
    raw = json.loads((root / "generated" / "tx_index.json").read_text(encoding="utf-8"))
    names = {str(row.get("name") or "") for row in raw.get("tx_types", [])}
    assert len(names) == 221
    assert "POH_EMAIL_ATTESTATION_SUBMIT" in names
    assert "POH_EMAIL_RECEIPT_SUBMIT" not in names
