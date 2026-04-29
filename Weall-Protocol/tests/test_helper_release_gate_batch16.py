from __future__ import annotations

from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from weall.runtime.helper_certificates import (
    HelperExecutionCertificate,
    make_namespace_hash,
    sign_helper_certificate,
)
from weall.runtime.helper_dispatch import HelperDispatchContext
from weall.runtime.helper_event_driver import HelperEvent, run_helper_event_sequence
from weall.runtime.helper_lane_journal import HelperLaneJournal
from weall.runtime.helper_merge_admission import (
    admit_helper_merge,
    canonical_receipts_root,
    canonical_state_delta_hash,
)
from weall.runtime.helper_proposal_loop import HelperProposalCycleInput, run_helper_proposal_loop
from weall.runtime.helper_release_gate import build_helper_release_gate_report
from weall.runtime.helper_restart_replay import build_helper_restart_snapshot
from weall.runtime.helper_soak_harness import HelperSoakPlan, run_helper_soak
from weall.runtime.parallel_execution import plan_parallel_execution


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


def _pub_hex_from_seed(seed_hex: str) -> str:
    key = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(seed_hex))
    return key.public_key().public_bytes_raw().hex()


def _mk_signed_cert(
    *,
    block_height: int,
    helper_id: str,
    lane_id: str,
    tx_ids: tuple[str, ...],
    seed_byte: int,
    receipts_root: str,
    lane_delta_hash: str,
):
    seed = (bytes([seed_byte]) * 32).hex()
    pub = _pub_hex_from_seed(seed)
    cert = sign_helper_certificate(
        HelperExecutionCertificate(
            chain_id="c1",
            block_height=int(block_height),
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
            lane_delta_hash=lane_delta_hash,
            namespace_hash=make_namespace_hash(["content:post:1"]),
        ),
        privkey=seed,
    )
    return cert, pub


def _context(block_height: int = 22):
    return HelperDispatchContext(
        chain_id="c1",
        block_height=int(block_height),
        view=7,
        leader_id="v1",
        validator_epoch=9,
        validator_set_hash="vhash",
    )


def _journal_factory(tmp_path: Path, prefix: str):
    def factory(idx: int):
        return HelperLaneJournal(str(tmp_path / f"{prefix}_{idx}.jsonl"))
    return factory


def test_helper_release_gate_bundle_batch16(tmp_path) -> None:
    lane_plans, lane_plan = _lane_setup()
    receipts_ok = [{"tx_id": "t1", "status": "ok"}]
    delta_ok = {"balances:alice": 5}
    receipts_root_ok = canonical_receipts_root(receipts_ok)
    delta_hash_ok = canonical_state_delta_hash(delta_ok)

    cert_22, pub = _mk_signed_cert(
        block_height=22,
        helper_id=lane_plan.helper_id,
        lane_id=lane_plan.lane_id,
        tx_ids=lane_plan.tx_ids,
        seed_byte=5,
        receipts_root=receipts_root_ok,
        lane_delta_hash=delta_hash_ok,
    )
    cert_conflict, _ = _mk_signed_cert(
        block_height=22,
        helper_id=lane_plan.helper_id,
        lane_id=lane_plan.lane_id,
        tx_ids=lane_plan.tx_ids,
        seed_byte=5,
        receipts_root="wrong-root",
        lane_delta_hash=delta_hash_ok,
    )

    replay_summary = run_helper_event_sequence(
        context=_context(22),
        lane_plans=lane_plans,
        helper_pubkeys={lane_plan.helper_id: pub},
        journal=HelperLaneJournal(str(tmp_path / "replay.jsonl")),
        helper_timeout_ms=50,
        events=(
            HelperEvent(kind="start", started_ms=1000),
            HelperEvent(kind="cert", cert=cert_22, peer_id=lane_plan.helper_id),
            HelperEvent(kind="cert", cert=cert_22, peer_id=lane_plan.helper_id),
        ),
    )
    deterministic_replay_ok = (
        replay_summary.finalized_modes == ((lane_plan.lane_id, "helper"),)
        and replay_summary.event_codes == ("start", "accepted", "duplicate_replay")
    )

    timeout_summary = run_helper_event_sequence(
        context=_context(22),
        lane_plans=lane_plans,
        journal=HelperLaneJournal(str(tmp_path / "timeout.jsonl")),
        helper_timeout_ms=50,
        events=(
            HelperEvent(kind="start", started_ms=1000),
            HelperEvent(kind="timeout", now_ms=1050),
        ),
    )
    timeout_fallback_ok = timeout_summary.finalized_modes == ((lane_plan.lane_id, "fallback"),)

    conflict_summary = run_helper_event_sequence(
        context=_context(22),
        lane_plans=lane_plans,
        helper_pubkeys={lane_plan.helper_id: pub},
        journal=HelperLaneJournal(str(tmp_path / "conflict.jsonl")),
        helper_timeout_ms=50,
        events=(
            HelperEvent(kind="start", started_ms=1000),
            HelperEvent(kind="cert", cert=cert_22, peer_id=lane_plan.helper_id),
            HelperEvent(kind="cert", cert=cert_conflict, peer_id=lane_plan.helper_id),
        ),
    )
    conflicting_replay_ok = conflict_summary.event_codes[-1] == "conflicting_replay"

    shared_restart = HelperLaneJournal(str(tmp_path / "restart.jsonl"))
    before = run_helper_event_sequence(
        context=_context(22),
        lane_plans=lane_plans,
        helper_pubkeys={lane_plan.helper_id: pub},
        journal=shared_restart,
        helper_timeout_ms=50,
        events=(
            HelperEvent(kind="start", started_ms=1000),
            HelperEvent(kind="cert", cert=cert_22, peer_id=lane_plan.helper_id),
        ),
    )
    HelperAssemblyProfile = __import__(
        "weall.runtime.helper_assembly_gate", fromlist=["HelperAssemblyProfile"]
    ).HelperAssemblyProfile
    snapshot1 = build_helper_restart_snapshot(
        profile=HelperAssemblyProfile(
            helper_mode_enabled=True,
            require_serial_equivalence=False,
            fail_closed_on_helper_error=True,
        ),
        context=_context(22),
        lane_plans=lane_plans,
        lane_results_by_id={lane_plan.lane_id: {"receipts": receipts_ok, "state_delta": delta_ok}},
        journal=shared_restart,
        helper_pubkeys={lane_plan.helper_id: pub},
        helper_timeout_ms=50,
    )
    snapshot2 = build_helper_restart_snapshot(
        profile=HelperAssemblyProfile(
            helper_mode_enabled=True,
            require_serial_equivalence=False,
            fail_closed_on_helper_error=True,
        ),
        context=_context(22),
        lane_plans=lane_plans,
        lane_results_by_id={lane_plan.lane_id: {"receipts": receipts_ok, "state_delta": delta_ok}},
        journal=shared_restart,
        helper_pubkeys={lane_plan.helper_id: pub},
        helper_timeout_ms=50,
    )
    restart_recovery_ok = (
        before.finalized_modes == ((lane_plan.lane_id, "helper"),)
        and snapshot1.snapshot_hash() == snapshot2.snapshot_hash()
    )

    HelperLaneResolution = __import__(
        "weall.runtime.helper_proposal_orchestrator", fromlist=["HelperLaneResolution"]
    ).HelperLaneResolution
    resolution = HelperLaneResolution(
        lane_id=lane_plan.lane_id,
        helper_id=lane_plan.helper_id,
        mode="helper",
        certificate=cert_22,
    )
    merge_decision = admit_helper_merge(
        resolutions=(resolution,),
        lane_results_by_id={lane_plan.lane_id: {"receipts": receipts_ok, "state_delta": delta_ok}},
    )
    merge_admission_ok = bool(merge_decision.accepted)

    fail_closed_cert, _ = _mk_signed_cert(
        block_height=301,
        helper_id=lane_plan.helper_id,
        lane_id=lane_plan.lane_id,
        tx_ids=lane_plan.tx_ids,
        seed_byte=5,
        receipts_root="wrong-root",
        lane_delta_hash=delta_hash_ok,
    )
    fail_closed_loop = run_helper_proposal_loop(
        base_context=_context(0),
        lane_plans=lane_plans,
        cycles=(
            HelperProposalCycleInput(
                block_height=301,
                events=(
                    HelperEvent(kind="start", started_ms=1000),
                    HelperEvent(kind="cert", cert=fail_closed_cert, peer_id=lane_plan.helper_id),
                ),
                lane_results_by_id={lane_plan.lane_id: {"receipts": receipts_ok, "state_delta": delta_ok}},
                require_serial_equivalence=False,
                fail_closed_on_helper_error=True,
            ),
        ),
        helper_pubkeys={lane_plan.helper_id: pub},
        journal_factory=_journal_factory(tmp_path, "fail_closed"),
        helper_timeout_ms=50,
    )
    fail_closed_ok = (
        fail_closed_loop.results[0].assembly_accepted is False
        and fail_closed_loop.results[0].assembly_code == "receipts_root_mismatch"
    )

    degrade_cert, _ = _mk_signed_cert(
        block_height=401,
        helper_id=lane_plan.helper_id,
        lane_id=lane_plan.lane_id,
        tx_ids=lane_plan.tx_ids,
        seed_byte=5,
        receipts_root=receipts_root_ok,
        lane_delta_hash=delta_hash_ok,
    )
    degrade_loop = run_helper_proposal_loop(
        base_context=_context(0),
        lane_plans=lane_plans,
        cycles=(
            HelperProposalCycleInput(
                block_height=401,
                events=(
                    HelperEvent(kind="start", started_ms=1000),
                    HelperEvent(kind="cert", cert=degrade_cert, peer_id=lane_plan.helper_id),
                ),
                lane_results_by_id={lane_plan.lane_id: {"receipts": receipts_ok, "state_delta": delta_ok}},
                require_serial_equivalence=True,
                fail_closed_on_helper_error=False,
            ),
        ),
        helper_pubkeys={lane_plan.helper_id: pub},
        journal_factory=_journal_factory(tmp_path, "degrade"),
        helper_timeout_ms=50,
        serial_equivalence_fn=lambda candidates: False,
    )
    serial_degrade_ok = (
        degrade_loop.results[0].assembly_accepted is True
        and degrade_loop.results[0].assembly_mode == "serial_only"
    )

    helper_certs = {}
    for height in (500, 502):
        helper_certs[height] = _mk_signed_cert(
            block_height=height,
            helper_id=lane_plan.helper_id,
            lane_id=lane_plan.lane_id,
            tx_ids=lane_plan.tx_ids,
            seed_byte=5,
            receipts_root=receipts_root_ok,
            lane_delta_hash=delta_hash_ok,
        )[0]
    soak_summary = run_helper_soak(
        base_context=_context(0),
        lane_plans=lane_plans,
        start_height=500,
        helper_cert_by_height=helper_certs,
        lane_results_by_id={lane_plan.lane_id: {"receipts": receipts_ok, "state_delta": delta_ok}},
        plan=HelperSoakPlan(
            rounds=4,
            helper_every_n=2,
            require_serial_equivalence=False,
            fail_closed_on_helper_error=True,
        ),
        helper_pubkeys={lane_plan.helper_id: pub},
        journal_factory=_journal_factory(tmp_path, "soak"),
        helper_timeout_ms=50,
    )
    soak_ok = (
        soak_summary.accepted_heights == (500, 501, 502, 503)
        and soak_summary.failed_heights == ()
        and soak_summary.fallback_heights == (501, 503)
    )

    report = build_helper_release_gate_report(
        deterministic_replay_ok=deterministic_replay_ok,
        timeout_fallback_ok=timeout_fallback_ok,
        conflicting_replay_ok=conflicting_replay_ok,
        restart_recovery_ok=restart_recovery_ok,
        merge_admission_ok=merge_admission_ok,
        fail_closed_ok=fail_closed_ok,
        serial_degrade_ok=serial_degrade_ok,
        soak_ok=soak_ok,
    )

    assert report.all_required_passed() is True
    assert report.total_gates == 8
    assert report.passed_gates == 8
    assert report.readiness_score == 100
