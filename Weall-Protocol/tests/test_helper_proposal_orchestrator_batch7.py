from __future__ import annotations

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from weall.runtime.helper_certificates import (
    HelperExecutionCertificate,
    make_namespace_hash,
    sign_helper_certificate,
)
from weall.runtime.helper_dispatch import HelperDispatchContext
from weall.runtime.helper_lane_journal import HelperLaneJournal
from weall.runtime.helper_proposal_orchestrator import HelperProposalOrchestrator
from weall.runtime.parallel_execution import plan_parallel_execution


def _pub_hex_from_seed(seed_hex: str) -> str:
    key = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(seed_hex))
    return key.public_key().public_bytes_raw().hex()


def _lane_setup():
    txs = [{"tx_id": "t1", "tx_type": "CONTENT_CREATE", "state_prefixes": ["content:post:1"]}]
    lane_plans = plan_parallel_execution(
        txs=txs,
        validators=["v1", "v2", "v3"],
        validator_set_hash="vhash",
        view=7,
        leader_id="v1",
    )
    lane_plan = next(plan for plan in lane_plans if plan.lane_id == "PARALLEL_CONTENT")
    return lane_plans, lane_plan


def _mk_signed_cert(*, helper_id: str, lane_id: str, tx_ids: tuple[str, ...], seed_byte: int, receipts_root: str = "receipts"):
    seed = (bytes([seed_byte]) * 32).hex()
    pub = _pub_hex_from_seed(seed)
    cert = sign_helper_certificate(
        HelperExecutionCertificate(
            chain_id="c1",
            block_height=22,
            view=7,
            leader_id="v1",
            helper_id=helper_id,
            validator_epoch=9,
            validator_set_hash="vhash",
            lane_id=lane_id,
            tx_ids=tx_ids,
            tx_order_hash="order",
            receipts_root=receipts_root,
            write_set_hash="writes",
            read_set_hash="reads",
            lane_delta_hash="delta",
            namespace_hash=make_namespace_hash(["content:post:1"]),
        ),
        privkey=seed,
    )
    return cert, pub


def _context():
    return HelperDispatchContext(
        chain_id="c1",
        block_height=22,
        view=7,
        leader_id="v1",
        validator_epoch=9,
        validator_set_hash="vhash",
    )


def test_orchestrator_accepts_helper_and_marks_lane_resolved_batch7() -> None:
    lane_plans, lane_plan = _lane_setup()
    cert, pub = _mk_signed_cert(
        helper_id=lane_plan.helper_id,
        lane_id=lane_plan.lane_id,
        tx_ids=lane_plan.tx_ids,
        seed_byte=5,
    )
    orch = HelperProposalOrchestrator(
        context=_context(),
        lane_plans=lane_plans,
        helper_pubkeys={lane_plan.helper_id: pub},
        helper_timeout_ms=50,
    )
    orch.start_collection(started_ms=1000)
    status = orch.ingest_certificate(cert=cert, peer_id=lane_plan.helper_id)
    assert status.accepted is True
    assert orch.all_lanes_resolved() is True
    resolved = orch.resolution_for_lane(lane_plan.lane_id)
    assert resolved is not None
    assert resolved.mode == "helper"
    assert resolved.certificate is not None


def test_orchestrator_finalizes_fallback_after_timeout_batch7() -> None:
    lane_plans, lane_plan = _lane_setup()
    orch = HelperProposalOrchestrator(
        context=_context(),
        lane_plans=lane_plans,
        helper_timeout_ms=50,
    )
    orch.start_collection(started_ms=1000)
    assert orch.finalize_timeouts(now_ms=1049) == ()
    fallback = orch.finalize_timeouts(now_ms=1050)
    assert len(fallback) == 1
    assert fallback[0].lane_id == lane_plan.lane_id
    assert fallback[0].mode == "fallback"
    assert orch.all_lanes_resolved() is True


def test_orchestrator_rejects_late_helper_after_fallback_batch7() -> None:
    lane_plans, lane_plan = _lane_setup()
    cert, pub = _mk_signed_cert(
        helper_id=lane_plan.helper_id,
        lane_id=lane_plan.lane_id,
        tx_ids=lane_plan.tx_ids,
        seed_byte=6,
    )
    orch = HelperProposalOrchestrator(
        context=_context(),
        lane_plans=lane_plans,
        helper_pubkeys={lane_plan.helper_id: pub},
        helper_timeout_ms=50,
    )
    orch.start_collection(started_ms=1000)
    orch.finalize_timeouts(now_ms=1050)
    late = orch.ingest_certificate(cert=cert, peer_id=lane_plan.helper_id)
    assert late.accepted is False
    assert late.code == "lane_already_resolved"


def test_orchestrator_recovery_preserves_fallback_decision_batch7(tmp_path) -> None:
    lane_plans, lane_plan = _lane_setup()
    journal = HelperLaneJournal(str(tmp_path / "helper_lane.jsonl"))

    orch1 = HelperProposalOrchestrator(
        context=_context(),
        lane_plans=lane_plans,
        journal=journal,
        helper_timeout_ms=50,
    )
    orch1.start_collection(started_ms=1000)
    orch1.finalize_timeouts(now_ms=1050)

    orch2 = HelperProposalOrchestrator(
        context=_context(),
        lane_plans=lane_plans,
        journal=journal,
        helper_timeout_ms=50,
    )
    resolved = orch2.resolution_for_lane(lane_plan.lane_id)
    assert resolved is not None
    assert resolved.mode == "fallback"
    assert orch2.all_lanes_resolved() is True


def test_orchestrator_recovery_preserves_helper_decision_batch7(tmp_path) -> None:
    lane_plans, lane_plan = _lane_setup()
    journal = HelperLaneJournal(str(tmp_path / "helper_lane.jsonl"))
    cert, pub = _mk_signed_cert(
        helper_id=lane_plan.helper_id,
        lane_id=lane_plan.lane_id,
        tx_ids=lane_plan.tx_ids,
        seed_byte=7,
        receipts_root="receipts-a",
    )

    orch1 = HelperProposalOrchestrator(
        context=_context(),
        lane_plans=lane_plans,
        helper_pubkeys={lane_plan.helper_id: pub},
        journal=journal,
        helper_timeout_ms=50,
    )
    orch1.start_collection(started_ms=1000)
    status = orch1.ingest_certificate(cert=cert, peer_id=lane_plan.helper_id)
    assert status.accepted is True

    orch2 = HelperProposalOrchestrator(
        context=_context(),
        lane_plans=lane_plans,
        helper_pubkeys={lane_plan.helper_id: pub},
        journal=journal,
        helper_timeout_ms=50,
    )
    resolved = orch2.resolution_for_lane(lane_plan.lane_id)
    assert resolved is not None
    assert resolved.mode == "helper"
    assert resolved.certificate is not None
    assert resolved.certificate.receipts_root == "receipts-a"
