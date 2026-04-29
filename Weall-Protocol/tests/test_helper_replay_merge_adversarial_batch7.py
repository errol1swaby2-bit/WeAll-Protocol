from __future__ import annotations

from helper_audit_testkit import dispatch_context, lane_setup, signed_lane_certificate, pub_hex_from_seed
from weall.runtime.helper_certificates import build_plan_misbehavior_proof, sign_helper_certificate
from weall.runtime.helper_merge_admission import admit_helper_merge
from weall.runtime.helper_proposal_orchestrator import HelperLaneResolution
from weall.runtime.helper_replay_guard import HelperReplayGuard
from weall.runtime.parallel_execution import (
    LanePlan,
    canonical_helper_execution_plan_fingerprint,
    verify_block_helper_plan_metadata,
    verify_vote_ready_helper_plan,
)
from weall.runtime.helper_dispatch import HelperDispatchContext
from weall.runtime.helper_proposal_orchestrator import HelperProposalOrchestrator


def test_helper_replay_batch_ingest_is_canonical_with_mixed_lane_order_batch7() -> None:
    txs = [
        {"tx_id": "c1", "tx_type": "CONTENT_CREATE", "state_prefixes": ["content:post:1"]},
        {"tx_id": "i1", "tx_type": "IDENTITY_UPDATE", "state_prefixes": ["identity:user:alice"]},
        {"tx_id": "n1", "tx_type": "NOTIFICATION_SUBSCRIBE", "state_prefixes": ["notify:@alice:dm"]},
    ]
    lane_plans, plan_id = lane_setup(txs=txs)
    helper_lanes = tuple(plan for plan in lane_plans if str(plan.helper_id or ""))
    assert len(helper_lanes) >= 2

    helper_pubkeys = {}
    certs = []
    for idx, lane_plan in enumerate(sorted(helper_lanes, key=lambda item: item.lane_id), start=1):
        cert, pub = signed_lane_certificate(lane_plan=lane_plan, seed_byte=20 + idx, plan_id=plan_id, receipts_root=f"r-{idx}")
        helper_pubkeys[str(lane_plan.helper_id)] = pub
        certs.append((cert, str(lane_plan.helper_id)))

    orchestrator = HelperProposalOrchestrator(
        context=dispatch_context(plan_id=plan_id),
        lane_plans=lane_plans,
        helper_pubkeys=helper_pubkeys,
        helper_timeout_ms=50,
    )
    orchestrator.start_collection(started_ms=1000)
    guard = HelperReplayGuard(orchestrator=orchestrator)

    outcomes = guard.ingest_certificates_batch(certificates=(certs[1], certs[0], *certs[2:]))
    assert tuple(item.lane_id for item in outcomes) == tuple(sorted(plan.lane_id for plan in helper_lanes))
    assert all(item.accepted for item in outcomes)


def test_helper_merge_rejects_lane_tx_ids_mismatch_batch7() -> None:
    lane_plan = LanePlan(lane_id="L1", helper_id="h1", txs=(), tx_ids=("t1", "t2"))
    resolution = HelperLaneResolution(lane_id="L1", helper_id="h1", mode="helper", certificate=None)
    decision = admit_helper_merge(
        resolutions=(resolution,),
        lane_results_by_id={
            "L1": {
                "receipts": ({"tx_id": "t2"}, {"tx_id": "t1"}),
                "state_delta": {"k": "v"},
                "tx_ids": ("t1", "t2"),
                "plan_id": "plan-1",
            }
        },
        lane_plan_by_id={"L1": lane_plan},
        expected_plan_id="plan-1",
    )
    assert decision.accepted is False
    assert decision.code == "lane_tx_ids_mismatch"


def test_vote_ready_helper_plan_rejects_certificate_plan_mismatch_batch7() -> None:
    lane_plan = LanePlan(lane_id="L1", helper_id="h1", txs=(), tx_ids=("t1",))
    from weall.runtime.parallel_execution import canonical_lane_plan_fingerprint
    ok, reason = verify_vote_ready_helper_plan(
        local_lane_plans=(lane_plan,),
        advertised_plan_id=canonical_lane_plan_fingerprint((lane_plan,)),
        helper_certificates={
            "L1": {
                "chain_id": "c1",
                "block_height": 1,
                "view": 1,
                "leader_id": "v1",
                "helper_id": "h1",
                "validator_epoch": 1,
                "validator_set_hash": "vh",
                "lane_id": "L1",
                "tx_ids": ("t1",),
                "tx_order_hash": "order",
                "receipts_root": "root",
                "write_set_hash": "writes",
                "read_set_hash": "reads",
                "lane_delta_hash": "delta",
                "namespace_hash": "ns",
                "plan_id": "wrong-plan",
                "helper_signature": "",
            }
        },
    )
    assert ok is False
    assert reason == "plan_id_mismatch" or reason.startswith("certificate_plan_id_mismatch")


def test_block_helper_plan_metadata_rejects_nested_certificate_plan_mismatch_batch7() -> None:
    lane = {"lane_id": "L1", "helper_id": "h1", "tx_ids": ["t1"], "descriptor_hash": "d1", "plan_id": ""}
    computed = canonical_helper_execution_plan_fingerprint((lane,))
    lane["plan_id"] = computed
    helper_execution = {
        "plan_id": computed,
        "lanes": [lane],
        "accepted_certificates": [{"lane_id": "L1", "helper_id": "h1", "plan_id": "wrong-plan"}],
    }
    ok, reason = verify_block_helper_plan_metadata(helper_execution=helper_execution, expected_plan_id="")
    assert ok is False
    assert reason == "helper_execution_certificate_plan_id_mismatch"


def test_plan_misbehavior_proof_uses_explicit_issued_ms_batch7() -> None:
    cert_a = sign_helper_certificate(
        chain_id="c1",
        height=5,
        validator_epoch=1,
        validator_set_hash="vh",
        parent_block_id="p1",
        lane_id="L1",
        helper_id="h1",
        lane_tx_ids=("t1",),
        descriptor_hash="d1",
        plan_id="plan-1",
        shared_secret="secret",
        issued_ms=1000,
    )
    cert_b = sign_helper_certificate(
        chain_id="c1",
        height=5,
        validator_epoch=1,
        validator_set_hash="vh",
        parent_block_id="p1",
        lane_id="L1",
        helper_id="h1",
        lane_tx_ids=("t1",),
        descriptor_hash="d2",
        plan_id="plan-1",
        shared_secret="secret",
        issued_ms=1001,
    )
    proof = build_plan_misbehavior_proof(certificate_a=cert_a, certificate_b=cert_b)
    assert proof is not None
    assert proof.created_ms == 1001
