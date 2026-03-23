from __future__ import annotations

from weall.runtime.helper_lane_journal import HelperLaneJournal


def test_helper_lane_journal_loads_resolution_state_batch28(tmp_path) -> None:
    journal = HelperLaneJournal(str(tmp_path / "journal.jsonl"))
    journal.append_plan(plan_id="plan-1", lanes=[{"lane_id": "lane-a", "tx_ids": ["t1"]}])
    journal.append_receipt_accept(plan_id="plan-1", lane_id="lane-a", helper_id="h1", receipt_fingerprint="fp-1")
    journal.append_receipt_reject(plan_id="plan-1", lane_id="lane-a", helper_id="h2", receipt_fingerprint="fp-2", reason="stale")
    journal.append_fallback(plan_id="plan-1", lane_id="lane-b", helper_id="h3")

    state = journal.load_resolution_state()
    assert state["plan_id"] == "plan-1"
    assert state["accepted_receipts"]["fp-1"]["helper_id"] == "h1"
    assert state["rejected_receipts"]["fp-2"]["reason"] == "stale"
    assert state["fallback_lanes"]["lane-b"]["helper_id"] == "h3"
