from __future__ import annotations

from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from weall.runtime.helper_certificates import (
    HelperExecutionCertificate,
    make_namespace_hash,
    sign_helper_certificate,
)
from weall.runtime.helper_dispatch import HelperDispatchContext
from weall.runtime.helper_event_driver import HelperEvent
from weall.runtime.helper_lane_journal import HelperLaneJournal
from weall.runtime.helper_stress_matrix import (
    HelperStressCase,
    build_equivalent_reorder_cases,
    run_helper_stress_cases,
)
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
    key = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(seed))
    pub = key.public_key().public_bytes_raw().hex()
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


def _journal_factory(tmp_path: Path):
    def factory(idx: int):
        return HelperLaneJournal(str(tmp_path / f"helper_lane_{idx}.jsonl"))
    return factory


def test_helper_stress_matrix_duplicate_delivery_equivalence_batch13(tmp_path) -> None:
    lane_plans, lane_plan = _lane_setup()
    cert, pub = _mk_signed_cert(
        helper_id=lane_plan.helper_id,
        lane_id=lane_plan.lane_id,
        tx_ids=lane_plan.tx_ids,
        seed_byte=5,
    )

    cases = build_equivalent_reorder_cases(
        prefix_events=(HelperEvent(kind="start", started_ms=1000),),
        reorderable_events=(
            HelperEvent(kind="cert", cert=cert, peer_id=lane_plan.helper_id),
            HelperEvent(kind="cert", cert=cert, peer_id=lane_plan.helper_id),
        ),
        suffix_events=(),
        name_prefix="dup_delivery",
    )

    summary = run_helper_stress_cases(
        context=_context(),
        lane_plans=lane_plans,
        cases=cases,
        helper_pubkeys={lane_plan.helper_id: pub},
        journal_factory=_journal_factory(tmp_path),
        helper_timeout_ms=50,
    )
    assert summary.result_count == 2
    assert summary.all_equivalent() is True
    for result in summary.results:
        assert result.resolved_lanes == (lane_plan.lane_id,)
        assert result.finalized_modes == ((lane_plan.lane_id, "helper"),)


def test_helper_stress_matrix_timeout_noop_idempotent_batch13(tmp_path) -> None:
    lane_plans, lane_plan = _lane_setup()
    cert, pub = _mk_signed_cert(
        helper_id=lane_plan.helper_id,
        lane_id=lane_plan.lane_id,
        tx_ids=lane_plan.tx_ids,
        seed_byte=6,
    )

    cases = (
        HelperStressCase(
            name="timeout_once",
            events=(
                HelperEvent(kind="start", started_ms=1000),
                HelperEvent(kind="timeout", now_ms=1050),
                HelperEvent(kind="timeout", now_ms=1050),
            ),
        ),
        HelperStressCase(
            name="timeout_then_late_cert_then_timeout",
            events=(
                HelperEvent(kind="start", started_ms=1000),
                HelperEvent(kind="timeout", now_ms=1050),
                HelperEvent(kind="cert", cert=cert, peer_id=lane_plan.helper_id),
                HelperEvent(kind="timeout", now_ms=1050),
            ),
        ),
    )

    summary = run_helper_stress_cases(
        context=_context(),
        lane_plans=lane_plans,
        cases=cases,
        helper_pubkeys={lane_plan.helper_id: pub},
        journal_factory=_journal_factory(tmp_path),
        helper_timeout_ms=50,
    )
    assert summary.result_count == 2
    # Different event codes are expected, but final state must match.
    assert len(summary.unique_outcome_hashes) == 2
    for result in summary.results:
        assert result.resolved_lanes == (lane_plan.lane_id,)
        assert result.finalized_modes == ((lane_plan.lane_id, "fallback"),)


def test_helper_stress_matrix_restart_equivalent_journal_reuse_batch13(tmp_path) -> None:
    lane_plans, lane_plan = _lane_setup()
    cert, pub = _mk_signed_cert(
        helper_id=lane_plan.helper_id,
        lane_id=lane_plan.lane_id,
        tx_ids=lane_plan.tx_ids,
        seed_byte=7,
    )
    shared_journal = HelperLaneJournal(str(tmp_path / "shared_helper_lane.jsonl"))

    case1 = HelperStressCase(
        name="initial_accept",
        events=(
            HelperEvent(kind="start", started_ms=1000),
            HelperEvent(kind="cert", cert=cert, peer_id=lane_plan.helper_id),
        ),
    )
    case2 = HelperStressCase(
        name="replay_after_restart",
        events=(
            HelperEvent(kind="cert", cert=cert, peer_id=lane_plan.helper_id),
        ),
    )

    summary1 = run_helper_stress_cases(
        context=_context(),
        lane_plans=lane_plans,
        cases=(case1,),
        helper_pubkeys={lane_plan.helper_id: pub},
        journal_factory=lambda idx: shared_journal,
        helper_timeout_ms=50,
    )
    summary2 = run_helper_stress_cases(
        context=_context(),
        lane_plans=lane_plans,
        cases=(case2,),
        helper_pubkeys={lane_plan.helper_id: pub},
        journal_factory=lambda idx: shared_journal,
        helper_timeout_ms=50,
    )

    result1 = summary1.results[0]
    result2 = summary2.results[0]
    assert result1.resolved_lanes == result2.resolved_lanes
    assert result1.finalized_modes == result2.finalized_modes
    assert result2.event_codes == ("duplicate_replay",)


def test_helper_stress_matrix_conflicting_replay_preserves_resolution_batch13(tmp_path) -> None:
    lane_plans, lane_plan = _lane_setup()
    cert1, pub1 = _mk_signed_cert(
        helper_id=lane_plan.helper_id,
        lane_id=lane_plan.lane_id,
        tx_ids=lane_plan.tx_ids,
        seed_byte=8,
        receipts_root="receipts-a",
    )
    cert2, _ = _mk_signed_cert(
        helper_id=lane_plan.helper_id,
        lane_id=lane_plan.lane_id,
        tx_ids=lane_plan.tx_ids,
        seed_byte=9,
        receipts_root="receipts-b",
    )

    cases = build_equivalent_reorder_cases(
        prefix_events=(HelperEvent(kind="start", started_ms=1000),),
        reorderable_events=(
            HelperEvent(kind="cert", cert=cert1, peer_id=lane_plan.helper_id),
            HelperEvent(kind="cert", cert=cert2, peer_id=lane_plan.helper_id),
        ),
        suffix_events=(),
        name_prefix="conflicting_delivery",
    )

    summary = run_helper_stress_cases(
        context=_context(),
        lane_plans=lane_plans,
        cases=cases,
        helper_pubkeys={lane_plan.helper_id: pub1},
        journal_factory=_journal_factory(tmp_path),
        helper_timeout_ms=50,
    )
    assert summary.result_count == 2
    # Order matters here because the first accepted certificate is authoritative.
    assert len(summary.unique_outcome_hashes) == 2
    for result in summary.results:
        assert result.resolved_lanes == (lane_plan.lane_id,)
        assert result.finalized_modes == ((lane_plan.lane_id, "helper"),)
