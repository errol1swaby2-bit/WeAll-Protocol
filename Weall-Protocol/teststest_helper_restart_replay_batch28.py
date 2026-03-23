from __future__ import annotations

from weall.runtime.helper_assembly_gate import HelperAssemblyProfile
from weall.runtime.helper_dispatch import HelperDispatchContext
from weall.runtime.helper_lane_journal import HelperLaneJournal
from weall.runtime.helper_restart_replay import build_helper_restart_snapshot
from weall.runtime.parallel_execution import LanePlan


def test_helper_restart_snapshot_surfaces_plan_ids_batch28(tmp_path) -> None:
    journal = HelperLaneJournal(str(tmp_path / "journal.jsonl"))
    journal.append_plan(plan_id="journal-plan", lanes=[{"lane_id": "lane-a", "tx_ids": ["t1"]}])
    lane_plans = (LanePlan(lane_id="lane-a", helper_id="h1", txs=(), tx_ids=("t1",)),)
    snapshot = build_helper_restart_snapshot(
        profile=HelperAssemblyProfile(helper_mode_enabled=False),
        context=HelperDispatchContext(chain_id="c1", block_height=1, view=1, leader_id="v1", validator_epoch=1, validator_set_hash="vh"),
        lane_plans=lane_plans,
        lane_results_by_id={},
        journal=journal,
    )
    assert snapshot.plan_id
    assert snapshot.journal_plan_id == "journal-plan"
