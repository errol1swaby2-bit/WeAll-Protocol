from __future__ import annotations

from helper_audit_testkit import dispatch_context, lane_setup, signed_lane_certificate
from weall.runtime.helper_proposal_orchestrator import HelperProposalOrchestrator
from weall.runtime.parallel_execution import verify_vote_ready_helper_plan


def test_competing_leader_certificate_is_rejected_for_same_height_and_view_batch9() -> None:
    txs = [{"tx_id": "t1", "tx_type": "CONTENT_CREATE", "state_prefixes": ["content:post:1"]}]
    lane_plans, plan_id = lane_setup(txs=txs, validators=("v1", "v2", "v3"), view=9, leader_id="v1")
    lane_plan = next(plan for plan in lane_plans if str(plan.helper_id or ""))

    cert, pub = signed_lane_certificate(
        lane_plan=lane_plan,
        seed_byte=41,
        plan_id=plan_id,
        leader_id="v2",
        view=9,
        block_height=22,
    )
    orchestrator = HelperProposalOrchestrator(
        context=dispatch_context(plan_id=plan_id),
        lane_plans=lane_plans,
        helper_pubkeys={str(lane_plan.helper_id): pub},
        helper_timeout_ms=50,
    )
    orchestrator.start_collection(started_ms=1000)
    status = orchestrator.ingest_certificate(cert=cert, peer_id=str(lane_plan.helper_id))
    assert status.accepted is False
    assert status.code == "leader_mismatch"



def test_competing_plan_id_certificate_is_rejected_for_same_context_batch9() -> None:
    txs = [{"tx_id": "t1", "tx_type": "CONTENT_CREATE", "state_prefixes": ["content:post:1"]}]
    lane_plans, plan_id = lane_setup(txs=txs, validators=("v1", "v2", "v3"), view=9, leader_id="v1")
    lane_plan = next(plan for plan in lane_plans if str(plan.helper_id or ""))

    cert, pub = signed_lane_certificate(
        lane_plan=lane_plan,
        seed_byte=42,
        plan_id="competing-plan-id",
    )
    orchestrator = HelperProposalOrchestrator(
        context=dispatch_context(plan_id=plan_id),
        lane_plans=lane_plans,
        helper_pubkeys={str(lane_plan.helper_id): pub},
        helper_timeout_ms=50,
    )
    orchestrator.start_collection(started_ms=1000)
    status = orchestrator.ingest_certificate(cert=cert, peer_id=str(lane_plan.helper_id))
    assert status.accepted is False
    assert status.code == "plan_id_mismatch"



def test_vote_ready_guard_rejects_competing_plan_even_with_matching_lane_certificate_batch9() -> None:
    txs = [
        {"tx_id": "t1", "tx_type": "CONTENT_CREATE", "state_prefixes": ["content:post:1"]},
        {"tx_id": "t2", "tx_type": "IDENTITY_UPDATE", "state_prefixes": ["identity:user:alice"]},
    ]
    lane_plans, plan_id = lane_setup(txs=txs, validators=("v1", "v2", "v3", "v4"), view=12, leader_id="v1")
    helper_lane = next(plan for plan in lane_plans if str(plan.helper_id or ""))
    cert, _pub = signed_lane_certificate(lane_plan=helper_lane, seed_byte=43, plan_id="remote-plan")

    ok, reason = verify_vote_ready_helper_plan(
        local_lane_plans=lane_plans,
        advertised_plan_id=plan_id,
        helper_certificates={str(helper_lane.lane_id): cert},
    )
    assert ok is False
    assert reason == f"certificate_plan_id_mismatch:{helper_lane.lane_id}"
