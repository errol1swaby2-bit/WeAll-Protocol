from __future__ import annotations

from pathlib import Path

from weall.runtime.bft_journal import BftJournal


def test_bft_journal_bootstrap_state_tracks_fetch_requests(tmp_path: Path) -> None:
    j = BftJournal(str(tmp_path / "j.jsonl"), max_events=100)
    j.append("bft_view_advanced", view=3)
    j.append("bft_fetch_requested", block_id="b1")
    j.append("bft_timeout_emitted", view=3, high_qc_id="q1")
    j.append("bft_fetch_satisfied", block_id="b1")
    st = j.bootstrap_state()
    assert int(st["last_view"]) == 3
    assert int(st["last_timeout_view"]) == 3
    assert st["last_high_qc_id"] == "q1"
    assert st["fetch_requests"] == []
