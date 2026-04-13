from __future__ import annotations

from helper_audit_testkit import dispatch_context, lane_setup, signed_lane_certificate
from weall.runtime.helper_lane_journal import HelperLaneJournal
from weall.runtime.helper_proposal_orchestrator import HelperProposalOrchestrator
from weall.runtime.helper_replay_guard import HelperReplayGuard


def test_helper_late_and_conflicting_replays_stay_rejected_after_restart_and_fallback_batch136(tmp_path) -> None:
    lane_plans, plan_id = lane_setup(
        txs=[
            {"tx_id": "c1", "tx_type": "CONTENT_CREATE", "state_prefixes": ["content:post:1"]},
            {"tx_id": "i1", "tx_type": "IDENTITY_UPDATE", "state_prefixes": ["identity:user:alice"]},
            {"tx_id": "t1", "tx_type": "TREASURY_CREATE", "state_prefixes": ["treasury:main"]},
        ]
    )
    helper_lanes = tuple(sorted((plan for plan in lane_plans if str(plan.helper_id or "")), key=lambda item: item.lane_id))
    assert len(helper_lanes) >= 2
    accepted_lane = helper_lanes[0]
    fallback_lane = helper_lanes[-1]

    accepted_cert, accepted_pub = signed_lane_certificate(
        lane_plan=accepted_lane,
        seed_byte=41,
        plan_id=plan_id,
        receipts_root="r-accepted",
        lane_delta_hash="d-accepted",
    )
    helper_pubkeys = {str(accepted_lane.helper_id): accepted_pub}

    journal = HelperLaneJournal(str(tmp_path / "helper-replay.jsonl"))
    orchestrator1 = HelperProposalOrchestrator(
        context=dispatch_context(plan_id=plan_id),
        lane_plans=lane_plans,
        helper_pubkeys=helper_pubkeys,
        journal=journal,
        helper_timeout_ms=50,
    )
    orchestrator1.start_collection(started_ms=1000)
    guard1 = HelperReplayGuard(orchestrator=orchestrator1, journal=journal)

    first = guard1.ingest_certificate(cert=accepted_cert, peer_id=str(accepted_lane.helper_id))
    assert first.accepted is True

    fallbacks = guard1.finalize_timeouts(now_ms=1051)
    assert any(item.lane_id == fallback_lane.lane_id and item.code == "fallback_finalized" for item in fallbacks)

    orchestrator2 = HelperProposalOrchestrator(
        context=dispatch_context(plan_id=plan_id),
        lane_plans=lane_plans,
        helper_pubkeys=helper_pubkeys,
        journal=journal,
        helper_timeout_ms=50,
    )
    guard2 = HelperReplayGuard(orchestrator=orchestrator2, journal=journal)

    late_duplicate = guard2.ingest_certificate(cert=accepted_cert, peer_id=str(accepted_lane.helper_id))
    assert late_duplicate.accepted is False
    assert late_duplicate.code == "duplicate_replay"

    conflicting_cert, _pub2 = signed_lane_certificate(
        lane_plan=accepted_lane,
        seed_byte=42,
        plan_id=plan_id,
        receipts_root="r-conflict",
        lane_delta_hash="d-conflict",
    )
    conflicting = guard2.ingest_certificate(cert=conflicting_cert, peer_id=str(accepted_lane.helper_id))
    assert conflicting.accepted is False
    assert conflicting.code == "conflicting_replay"

    fallback_cert, _pub3 = signed_lane_certificate(
        lane_plan=fallback_lane,
        seed_byte=43,
        plan_id=plan_id,
        receipts_root="r-fallback",
        lane_delta_hash="d-fallback",
    )
    late_fallback = guard2.ingest_certificate(cert=fallback_cert, peer_id=str(fallback_lane.helper_id or "peer-fallback"))
    assert late_fallback.accepted is False
    assert late_fallback.code == "lane_already_resolved_fallback"
