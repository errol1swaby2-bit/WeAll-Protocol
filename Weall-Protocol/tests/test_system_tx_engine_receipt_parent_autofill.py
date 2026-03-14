from __future__ import annotations

from weall.runtime.system_tx_engine import enqueue_system_tx, system_tx_emitter


def _canon_stub_with_receipt(*, tx_type: str, parent: str) -> dict:
    # Minimal dict-shim compatible with system_tx_engine._canon_info()
    return {
        "by_name": {
            tx_type: {
                "context": "block",
                "receipt_only": True,
                "system_only": True,
                "parent": parent,
            }
        }
    }


def test_receipt_only_system_tx_parent_is_autofilled_from_canon_when_missing() -> None:
    ledger = {"height": 0, "system_queue": []}
    canon = _canon_stub_with_receipt(tx_type="R", parent="P")

    # Enqueue a receipt-only tx WITHOUT an explicit parent.
    enqueue_system_tx(
        ledger,
        tx_type="R",
        payload={"k": "v"},
        due_height=1,
        signer="SYSTEM",
        once=True,
        parent=None,
        phase="post",
    )

    out = system_tx_emitter(ledger, canon=canon, next_height=1, phase="post")
    assert len(out) == 1
    assert out[0].tx_type == "R"
    assert out[0].system is True
    assert out[0].parent == "P"
