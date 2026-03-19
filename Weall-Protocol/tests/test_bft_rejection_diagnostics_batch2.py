from __future__ import annotations

from pathlib import Path

from weall.runtime.bft_journal import BftJournal


def test_bft_journal_tail_preserves_recent_rejection_diagnostics(tmp_path: Path) -> None:
    j = BftJournal(str(tmp_path / "j.jsonl"), max_events=10)
    j.append("bft_message_rejected", message_type="proposal", reason="missing_parent")
    j.append("bft_message_rejected", message_type="qc", reason="unknown_block")
    tail = j.read_tail(limit=10)
    assert len(tail) == 2
    assert tail[-1]["event"] == "bft_message_rejected"
    assert tail[-1]["payload"]["reason"] == "unknown_block"
