from __future__ import annotations

from pathlib import Path

from m3_closure_v2.receipts import ReceiptStore


def test_receipt_resume_requires_unchanged_output(tmp_path: Path) -> None:
    output = tmp_path / "result.json"
    output.write_text('{"ok":true}\n', encoding="utf-8")
    store = ReceiptStore(tmp_path / "receipts")

    receipt = store.create_passed(
        stage="verify",
        input_fingerprint="input-a",
        started_at_unix_ms=1,
        output_paths=[output],
        metadata={"count": 1},
    )

    assert store.valid_pass(
        stage="verify",
        input_fingerprint="input-a",
    ) == receipt

    output.write_text('{"ok":false}\n', encoding="utf-8")
    assert store.valid_pass(
        stage="verify",
        input_fingerprint="input-a",
    ) is None
