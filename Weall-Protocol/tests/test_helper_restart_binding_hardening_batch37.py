from __future__ import annotations

from helper_audit_testkit import dispatch_context, lane_setup, signed_lane_certificate
from weall.runtime.helper_assembly_gate import HelperAssemblyProfile
from weall.runtime.helper_lane_journal import HelperLaneJournal
from weall.runtime.helper_merge_admission import canonical_receipts_root, canonical_state_delta_hash
from weall.runtime.helper_replay_guard import HelperReplayGuard
from weall.runtime.helper_restart_replay import build_helper_restart_snapshot
from weall.runtime.helper_proposal_orchestrator import HelperProposalOrchestrator


def test_helper_restart_snapshot_rejects_conflicting_journal_plan_history_batch37(tmp_path) -> None:
    txs = [{"tx_id": "t1", "tx_type": "CONTENT_CREATE", "state_prefixes": ["content:post:1"]}]
    lane_plans, plan_id = lane_setup(txs=txs)
    lane_plan = next(plan for plan in lane_plans if str(plan.helper_id or ""))
    journal = HelperLaneJournal(str(tmp_path / "helper-conflict-history.jsonl"))
    journal.append_plan(
        plan_id="wrong-plan",
        lanes=[{"lane_id": str(lane_plan.lane_id), "helper_id": str(lane_plan.helper_id or ""), "tx_ids": list(lane_plan.tx_ids)}],
    )

    snapshot = build_helper_restart_snapshot(
        profile=HelperAssemblyProfile(helper_mode_enabled=True),
        context=dispatch_context(plan_id=plan_id),
        lane_plans=lane_plans,
        lane_results_by_id={
            str(lane_plan.lane_id): {
                "receipts": [{"tx_id": "t1", "ok": True}],
                "state_delta": {"state/content/1": "ok"},
                "tx_ids": tuple(lane_plan.tx_ids),
                "plan_id": plan_id,
            }
        },
        journal=journal,
        helper_pubkeys={},
        helper_timeout_ms=50,
        serial_equivalence_fn=lambda candidates: True,
    )

    assert snapshot.assembly_accepted is False
    assert snapshot.assembly_mode == "helper_assisted"
    assert snapshot.assembly_code == "journal_history_plan_id_mismatch"


def test_helper_replay_guard_ignores_unknown_recovered_lanes_batch37(tmp_path) -> None:
    txs = [{"tx_id": "t1", "tx_type": "CONTENT_CREATE", "state_prefixes": ["content:post:1"]}]
    lane_plans, plan_id = lane_setup(txs=txs)
    lane_plan = next(plan for plan in lane_plans if str(plan.helper_id or ""))
    journal = HelperLaneJournal(str(tmp_path / "helper-unknown-lane.jsonl"))
    journal.append({
        "kind": "fallback_finalized",
        "plan_id": plan_id,
        "lane_id": "UNKNOWN_LANE",
        "helper_id": "h-bad",
    })

    orchestrator = HelperProposalOrchestrator(
        context=dispatch_context(plan_id=plan_id),
        lane_plans=lane_plans,
        journal=journal,
        helper_timeout_ms=50,
    )
    guard = HelperReplayGuard(orchestrator=orchestrator, journal=journal)

    assert guard.resolved_lanes() == ()
    assert orchestrator.finalized_resolutions() == ()


def test_helper_restart_recovery_ignores_helper_id_mismatch_batch37(tmp_path) -> None:
    txs = [{"tx_id": "t1", "tx_type": "CONTENT_CREATE", "state_prefixes": ["content:post:1"]}]
    lane_plans, plan_id = lane_setup(txs=txs)
    lane_plan = next(plan for plan in lane_plans if str(plan.helper_id or ""))
    journal = HelperLaneJournal(str(tmp_path / "helper-id-mismatch.jsonl"))

    receipts = [{"tx_id": "t1", "ok": True}]
    state_delta = {"state/content/1": "ok"}
    cert, _pub = signed_lane_certificate(
        lane_plan=lane_plan,
        seed_byte=55,
        plan_id=plan_id,
        helper_id="wrong-helper",
        receipts_root=canonical_receipts_root(receipts),
        lane_delta_hash=canonical_state_delta_hash(state_delta),
    )
    journal.append(
        {
            "kind": "helper_finalized",
            "lane_id": str(lane_plan.lane_id),
            "helper_id": "wrong-helper",
            "certificate": cert.to_json(),
            "plan_id": plan_id,
        }
    )

    orchestrator = HelperProposalOrchestrator(
        context=dispatch_context(plan_id=plan_id),
        lane_plans=lane_plans,
        journal=journal,
        helper_timeout_ms=50,
    )
    guard = HelperReplayGuard(orchestrator=orchestrator, journal=journal)

    assert orchestrator.finalized_resolutions() == ()
    assert guard.resolved_lanes() == ()
