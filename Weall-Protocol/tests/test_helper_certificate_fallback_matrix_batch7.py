from __future__ import annotations

from helper_audit_testkit import dispatch_context, first_helper_lane, lane_setup, signed_lane_certificate
from weall.runtime.helper_dispatch import HelperCertificateStore
from weall.runtime.helper_replay_guard import HelperReplayGuard
from weall.runtime.helper_proposal_orchestrator import HelperProposalOrchestrator


def _basic_lane_setup():
    txs = [{"tx_id": "c1", "tx_type": "CONTENT_CREATE", "state_prefixes": ["content:post:1"]}]
    lane_plans, plan_id = lane_setup(txs=txs)
    lane_plan = first_helper_lane(lane_plans)
    return lane_plans, lane_plan, plan_id


def test_helper_store_rejects_bad_signature_even_with_correct_peer_batch7() -> None:
    lane_plans, lane_plan, plan_id = _basic_lane_setup()
    cert, _ = signed_lane_certificate(lane_plan=lane_plan, seed_byte=11, plan_id=plan_id)
    _, wrong_pub = signed_lane_certificate(lane_plan=lane_plan, seed_byte=12, plan_id=plan_id)
    store = HelperCertificateStore(
        context=dispatch_context(plan_id=plan_id),
        lane_plans=lane_plans,
        helper_pubkeys={str(lane_plan.helper_id): wrong_pub},
    )
    store.start_request(lane_id=lane_plan.lane_id, started_ms=1000)
    status = store.ingest_certificate(cert=cert, peer_id=str(lane_plan.helper_id))
    assert status.accepted is False
    assert status.code == "bad_signature"


def test_helper_store_rejects_request_not_started_batch7() -> None:
    txs = [
        {"tx_id": "c1", "tx_type": "CONTENT_CREATE", "state_prefixes": ["content:post:1"]},
        {"tx_id": "i1", "tx_type": "IDENTITY_UPDATE", "state_prefixes": ["identity:user:alice"]},
    ]
    lane_plans, plan_id = lane_setup(txs=txs)
    helper_lanes = tuple(plan for plan in lane_plans if str(plan.helper_id or ""))
    assert len(helper_lanes) >= 2
    started_lane = helper_lanes[0]
    late_lane = helper_lanes[1]
    cert, pub = signed_lane_certificate(lane_plan=late_lane, seed_byte=13, plan_id=plan_id)
    store = HelperCertificateStore(
        context=dispatch_context(plan_id=plan_id),
        lane_plans=lane_plans,
        helper_pubkeys={str(late_lane.helper_id): pub},
    )
    store.start_request(lane_id=started_lane.lane_id, started_ms=1000)
    status = store.ingest_certificate(cert=cert, peer_id=str(late_lane.helper_id))
    assert status.accepted is False
    assert status.code == "request_not_started"


def test_helper_store_rejects_closed_request_window_batch7() -> None:
    lane_plans, lane_plan, plan_id = _basic_lane_setup()
    cert, pub = signed_lane_certificate(lane_plan=lane_plan, seed_byte=14, plan_id=plan_id)
    store = HelperCertificateStore(
        context=dispatch_context(plan_id=plan_id),
        lane_plans=lane_plans,
        helper_pubkeys={str(lane_plan.helper_id): pub},
        helper_timeout_ms=50,
    )
    store.start_request(lane_id=lane_plan.lane_id, started_ms=1000)
    status = store.ingest_certificate(cert=cert, peer_id=str(lane_plan.helper_id), now_ms=1050)
    assert status.accepted is False
    assert status.code == "request_window_closed"


def test_helper_store_rejects_manifest_hash_mismatch_batch7() -> None:
    lane_plans, lane_plan, plan_id = _basic_lane_setup()
    cert, pub = signed_lane_certificate(lane_plan=lane_plan, seed_byte=15, plan_id=plan_id, manifest_hash="manifest-a")
    store = HelperCertificateStore(
        context=dispatch_context(plan_id=plan_id, manifest_hash="manifest-b"),
        lane_plans=lane_plans,
        helper_pubkeys={str(lane_plan.helper_id): pub},
    )
    store.start_request(lane_id=lane_plan.lane_id, started_ms=1000)
    status = store.ingest_certificate(cert=cert, peer_id=str(lane_plan.helper_id))
    assert status.accepted is False
    assert status.code == "manifest_hash_mismatch"


def test_helper_replay_guard_recovers_fallback_resolution_after_restart_batch7(tmp_path) -> None:
    from weall.runtime.helper_lane_journal import HelperLaneJournal

    lane_plans, lane_plan, plan_id = _basic_lane_setup()
    journal = HelperLaneJournal(str(tmp_path / "helper-lanes.jsonl"))
    orchestrator1 = HelperProposalOrchestrator(
        context=dispatch_context(plan_id=plan_id),
        lane_plans=lane_plans,
        journal=journal,
        helper_timeout_ms=50,
    )
    orchestrator1.start_collection(started_ms=1000)
    guard1 = HelperReplayGuard(orchestrator=orchestrator1, journal=journal)
    fallback = guard1.finalize_timeouts(now_ms=1050)
    assert len(fallback) == 1
    assert fallback[0].code == "fallback_finalized"

    orchestrator2 = HelperProposalOrchestrator(
        context=dispatch_context(plan_id=plan_id),
        lane_plans=lane_plans,
        journal=journal,
        helper_timeout_ms=50,
    )
    guard2 = HelperReplayGuard(orchestrator=orchestrator2, journal=journal)
    recovered = guard2.resolution_outcome_for_lane(lane_plan.lane_id)
    assert recovered is not None
    assert recovered.code == "resolved:fallback"
