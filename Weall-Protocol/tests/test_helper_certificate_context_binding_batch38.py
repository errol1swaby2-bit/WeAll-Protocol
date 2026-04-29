from __future__ import annotations

from helper_audit_testkit import dispatch_context, lane_setup, signed_lane_certificate
from weall.runtime.helper_dispatch import HelperCertificateStore
from weall.runtime.helper_lane_journal import HelperLaneJournal
from weall.runtime.helper_proposal_orchestrator import HelperProposalOrchestrator


def test_helper_store_recovery_ignores_wrong_block_height_batch38(tmp_path) -> None:
    txs = [{"tx_id": "t1", "tx_type": "CONTENT_CREATE", "state_prefixes": ["content:post:1"]}]
    lane_plans, plan_id = lane_setup(txs=txs)
    lane_plan = next(plan for plan in lane_plans if str(plan.helper_id or ""))
    journal = HelperLaneJournal(str(tmp_path / "store-height-mismatch.jsonl"))

    cert, _pub = signed_lane_certificate(
        lane_plan=lane_plan,
        seed_byte=61,
        plan_id=plan_id,
        block_height=23,
    )
    journal.append(
        {
            "kind": "certificate_accepted",
            "lane_id": str(lane_plan.lane_id),
            "helper_id": str(lane_plan.helper_id or ""),
            "certificate": cert.to_json(),
            "plan_id": plan_id,
        }
    )

    store = HelperCertificateStore(
        context=dispatch_context(plan_id=plan_id),
        lane_plans=lane_plans,
        journal=journal,
    )

    assert store.accepted_certificates() == {}


def test_helper_orchestrator_recovery_ignores_wrong_view_batch38(tmp_path) -> None:
    txs = [{"tx_id": "t1", "tx_type": "CONTENT_CREATE", "state_prefixes": ["content:post:1"]}]
    lane_plans, plan_id = lane_setup(txs=txs)
    lane_plan = next(plan for plan in lane_plans if str(plan.helper_id or ""))
    journal = HelperLaneJournal(str(tmp_path / "orchestrator-view-mismatch.jsonl"))

    cert, _pub = signed_lane_certificate(
        lane_plan=lane_plan,
        seed_byte=62,
        plan_id=plan_id,
        view=8,
    )
    journal.append(
        {
            "kind": "helper_finalized",
            "lane_id": str(lane_plan.lane_id),
            "helper_id": str(lane_plan.helper_id or ""),
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

    assert orchestrator.finalized_resolutions() == ()


def test_helper_orchestrator_recovery_ignores_wrong_leader_batch38(tmp_path) -> None:
    txs = [{"tx_id": "t1", "tx_type": "CONTENT_CREATE", "state_prefixes": ["content:post:1"]}]
    lane_plans, plan_id = lane_setup(txs=txs)
    lane_plan = next(plan for plan in lane_plans if str(plan.helper_id or ""))
    journal = HelperLaneJournal(str(tmp_path / "orchestrator-leader-mismatch.jsonl"))

    cert, _pub = signed_lane_certificate(
        lane_plan=lane_plan,
        seed_byte=63,
        plan_id=plan_id,
        leader_id="v2",
    )
    journal.append(
        {
            "kind": "helper_finalized",
            "lane_id": str(lane_plan.lane_id),
            "helper_id": str(lane_plan.helper_id or ""),
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

    assert orchestrator.finalized_resolutions() == ()
