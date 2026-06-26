from __future__ import annotations

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from weall.runtime.helper_certificates import (
    HelperExecutionCertificate,
    make_namespace_hash,
    sign_helper_certificate,
)
from weall.runtime.helper_dispatch import HelperDispatchContext
from weall.runtime.helper_event_driver import (
    HelperEvent,
    run_helper_event_sequence,
)
from weall.runtime.helper_lane_journal import HelperLaneJournal
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


def test_event_driver_duplicate_delivery_same_final_outcome_batch12(tmp_path) -> None:
    lane_plans, lane_plan = _lane_setup()
    cert, pub = _mk_signed_cert(
        helper_id=lane_plan.helper_id,
        lane_id=lane_plan.lane_id,
        tx_ids=lane_plan.tx_ids,
        seed_byte=5,
    )
    summary = run_helper_event_sequence(
        context=_context(),
        lane_plans=lane_plans,
        helper_pubkeys={lane_plan.helper_id: pub},
        journal=HelperLaneJournal(str(tmp_path / "helper_lane.jsonl")),
        helper_timeout_ms=50,
        events=(
            HelperEvent(kind="start", started_ms=1000),
            HelperEvent(kind="cert", cert=cert, peer_id=lane_plan.helper_id),
            HelperEvent(kind="cert", cert=cert, peer_id=lane_plan.helper_id),
        ),
    )
    assert summary.resolved_lanes == (lane_plan.lane_id,)
    assert summary.finalized_modes == ((lane_plan.lane_id, "helper"),)
    assert summary.event_codes == ("start", "accepted", "duplicate_replay")


def test_event_driver_conflicting_replay_does_not_change_final_resolution_batch12(tmp_path) -> None:
    lane_plans, lane_plan = _lane_setup()
    cert1, pub1 = _mk_signed_cert(
        helper_id=lane_plan.helper_id,
        lane_id=lane_plan.lane_id,
        tx_ids=lane_plan.tx_ids,
        seed_byte=6,
        receipts_root="receipts-a",
    )
    cert2, _ = _mk_signed_cert(
        helper_id=lane_plan.helper_id,
        lane_id=lane_plan.lane_id,
        tx_ids=lane_plan.tx_ids,
        seed_byte=7,
        receipts_root="receipts-b",
    )
    summary = run_helper_event_sequence(
        context=_context(),
        lane_plans=lane_plans,
        helper_pubkeys={lane_plan.helper_id: pub1},
        journal=HelperLaneJournal(str(tmp_path / "helper_lane.jsonl")),
        helper_timeout_ms=50,
        events=(
            HelperEvent(kind="start", started_ms=1000),
            HelperEvent(kind="cert", cert=cert1, peer_id=lane_plan.helper_id),
            HelperEvent(kind="cert", cert=cert2, peer_id=lane_plan.helper_id),
        ),
    )
    assert summary.resolved_lanes == (lane_plan.lane_id,)
    assert summary.finalized_modes == ((lane_plan.lane_id, "helper"),)
    assert summary.event_codes == ("start", "accepted", "conflicting_replay")


def test_event_driver_timeout_then_late_helper_is_stable_batch12(tmp_path) -> None:
    lane_plans, lane_plan = _lane_setup()
    cert, pub = _mk_signed_cert(
        helper_id=lane_plan.helper_id,
        lane_id=lane_plan.lane_id,
        tx_ids=lane_plan.tx_ids,
        seed_byte=8,
    )
    summary = run_helper_event_sequence(
        context=_context(),
        lane_plans=lane_plans,
        helper_pubkeys={lane_plan.helper_id: pub},
        journal=HelperLaneJournal(str(tmp_path / "helper_lane.jsonl")),
        helper_timeout_ms=50,
        events=(
            HelperEvent(kind="start", started_ms=1000),
            HelperEvent(kind="timeout", now_ms=1050),
            HelperEvent(kind="cert", cert=cert, peer_id=lane_plan.helper_id),
            HelperEvent(kind="timeout", now_ms=1050),
        ),
    )
    assert summary.resolved_lanes == (lane_plan.lane_id,)
    assert summary.finalized_modes == ((lane_plan.lane_id, "fallback"),)
    assert summary.event_codes == (
        "start",
        "fallback_finalized",
        "lane_already_resolved_fallback",
        "timeout_noop",
    )


def test_event_driver_restart_equivalent_when_reusing_journal_batch12(tmp_path) -> None:
    lane_plans, lane_plan = _lane_setup()
    cert, pub = _mk_signed_cert(
        helper_id=lane_plan.helper_id,
        lane_id=lane_plan.lane_id,
        tx_ids=lane_plan.tx_ids,
        seed_byte=9,
    )
    journal = HelperLaneJournal(str(tmp_path / "helper_lane.jsonl"))
    summary1 = run_helper_event_sequence(
        context=_context(),
        lane_plans=lane_plans,
        helper_pubkeys={lane_plan.helper_id: pub},
        journal=journal,
        helper_timeout_ms=50,
        events=(
            HelperEvent(kind="start", started_ms=1000),
            HelperEvent(kind="cert", cert=cert, peer_id=lane_plan.helper_id),
        ),
    )
    summary2 = run_helper_event_sequence(
        context=_context(),
        lane_plans=lane_plans,
        helper_pubkeys={lane_plan.helper_id: pub},
        journal=journal,
        helper_timeout_ms=50,
        events=(
            HelperEvent(kind="cert", cert=cert, peer_id=lane_plan.helper_id),
        ),
    )
    assert summary1.resolved_lanes == summary2.resolved_lanes
    assert summary1.finalized_modes == summary2.finalized_modes
    assert summary2.event_codes == ("duplicate_replay",)
