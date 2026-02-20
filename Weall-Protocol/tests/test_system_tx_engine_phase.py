from __future__ import annotations

from weall.runtime.system_tx_engine import enqueue_system_tx, system_tx_emitter


def _canon_stub(*tx_types: str):
    # Minimal shape compatible with system_tx_engine._canon_context()
    return {
        "by_name": {t: {"context": "block", "receipt_only": False} for t in tx_types}
    }


def test_system_tx_emitter_phase_does_not_consume_other_phase() -> None:
    ledger = {"height": 0, "system_queue": []}
    canon = _canon_stub("A_PRE", "B_POST")

    enqueue_system_tx(
        ledger,
        tx_type="A_PRE",
        payload={"x": 1},
        due_height=1,
        phase="pre",
        once=True,
    )
    enqueue_system_tx(
        ledger,
        tx_type="B_POST",
        payload={"y": 2},
        due_height=1,
        phase="post",
        once=True,
    )

    pre = system_tx_emitter(ledger, canon=canon, next_height=1, phase="pre")
    assert [t.tx_type for t in pre] == ["A_PRE"]

    # Post item should still be un-emitted
    q = ledger["system_queue"]
    post_entries = [e for e in q if isinstance(e, dict) and e.get("tx_type") == "B_POST"]
    assert len(post_entries) == 1
    assert post_entries[0].get("emitted_height") is None

    post = system_tx_emitter(ledger, canon=canon, next_height=1, phase="post")
    assert [t.tx_type for t in post] == ["B_POST"]
