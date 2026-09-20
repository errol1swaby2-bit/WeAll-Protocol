from __future__ import annotations

from weall.runtime.system_tx_engine import enqueue_system_tx, system_tx_emitter


def _canon_stub_with_receipt(*, tx_type: str, parent_tx_type: str) -> dict:
    return {
        "by_name": {
            tx_type: {
                "context": "block",
                "receipt_only": True,
                "system_only": True,
                "parent_tx_type": parent_tx_type,
            }
        }
    }


def test_receipt_parent_tx_type_is_not_synthesized_as_concrete_parent_ref() -> None:
    ledger = {"height": 0, "system_queue": []}
    canon = _canon_stub_with_receipt(tx_type="R", parent_tx_type="P")
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
    assert out[0].parent is None
    assert "_parent_ref" not in out[0].payload


def test_explicit_concrete_parent_ref_round_trips_unchanged() -> None:
    ledger = {"height": 0, "system_queue": []}
    canon = _canon_stub_with_receipt(tx_type="R", parent_tx_type="P")
    enqueue_system_tx(
        ledger,
        tx_type="R",
        payload={"k": "v"},
        due_height=1,
        signer="SYSTEM",
        once=True,
        parent="tx:parent:1",
        phase="post",
    )
    out = system_tx_emitter(ledger, canon=canon, next_height=1, phase="post")
    assert len(out) == 1
    assert out[0].parent == "tx:parent:1"
    assert out[0].payload["_parent_ref"] == "tx:parent:1"
