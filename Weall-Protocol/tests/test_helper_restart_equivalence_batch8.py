from __future__ import annotations

from helper_audit_testkit import dispatch_context, lane_setup, signed_lane_certificate
from weall.runtime.helper_assembly_gate import HelperAssemblyProfile
from weall.runtime.helper_lane_journal import HelperLaneJournal
from weall.runtime.helper_merge_admission import canonical_receipts_root, canonical_state_delta_hash
from weall.runtime.helper_replay_guard import HelperReplayGuard
from weall.runtime.helper_restart_replay import build_helper_restart_snapshot
from weall.runtime.helper_proposal_orchestrator import HelperProposalOrchestrator


MULTILANE_TXS = [
    {"tx_id": "c1", "tx_type": "CONTENT_CREATE", "state_prefixes": ["content:post:1"]},
    {"tx_id": "i1", "tx_type": "IDENTITY_UPDATE", "state_prefixes": ["identity:user:alice"]},
    {"tx_id": "t1", "tx_type": "TREASURY_CREATE", "state_prefixes": ["treasury:main"]},
]


def _materialize_lane_results(*, lane_plans, plan_id: str, shared_key: str | None = None):
    lane_results_by_id = {}
    helper_pubkeys = {}
    certs = []
    helper_lanes = tuple(sorted((plan for plan in lane_plans if str(plan.helper_id or "")), key=lambda item: item.lane_id))
    assert len(helper_lanes) >= 3
    fallback_lane = helper_lanes[-1]
    accepted_lanes = helper_lanes[:-1]
    helper_seed_by_id: dict[str, int] = {}
    next_seed = 41
    for idx, lane_plan in enumerate(helper_lanes, start=1):
        receipts = [{"tx_id": tx_id, "ok": True, "lane_id": lane_plan.lane_id} for tx_id in lane_plan.tx_ids]
        delta_key = shared_key if shared_key else f"state/{lane_plan.lane_id.lower()}"
        state_delta = {delta_key if lane_plan in accepted_lanes else f"state/{lane_plan.lane_id.lower()}": f"value-{idx}"}
        lane_results_by_id[str(lane_plan.lane_id)] = {
            "receipts": tuple(receipts),
            "state_delta": state_delta,
            "tx_ids": tuple(lane_plan.tx_ids),
            "plan_id": plan_id,
        }
        if lane_plan in accepted_lanes:
            helper_id = str(lane_plan.helper_id or "")
            seed_byte = helper_seed_by_id.get(helper_id)
            if seed_byte is None:
                seed_byte = next_seed
                helper_seed_by_id[helper_id] = seed_byte
                next_seed += 1
            cert, pub = signed_lane_certificate(
                lane_plan=lane_plan,
                seed_byte=seed_byte,
                plan_id=plan_id,
                receipts_root=canonical_receipts_root(receipts),
                lane_delta_hash=canonical_state_delta_hash(state_delta),
            )
            helper_pubkeys[str(lane_plan.helper_id)] = pub
            certs.append((cert, str(lane_plan.helper_id)))
    return helper_lanes, accepted_lanes, fallback_lane, lane_results_by_id, helper_pubkeys, tuple(certs)


def test_helper_restart_snapshot_is_restart_equivalent_with_mixed_helper_and_fallback_batch8(tmp_path) -> None:
    lane_plans, plan_id = lane_setup(txs=MULTILANE_TXS)
    helper_lanes, _accepted_lanes, _fallback_lane, lane_results_by_id, helper_pubkeys, certs = _materialize_lane_results(
        lane_plans=lane_plans,
        plan_id=plan_id,
    )

    journal = HelperLaneJournal(str(tmp_path / "helper-lanes.jsonl"))
    orchestrator1 = HelperProposalOrchestrator(
        context=dispatch_context(plan_id=plan_id),
        lane_plans=lane_plans,
        helper_pubkeys=helper_pubkeys,
        journal=journal,
        helper_timeout_ms=50,
    )
    orchestrator1.start_collection(started_ms=1000)
    guard1 = HelperReplayGuard(orchestrator=orchestrator1, journal=journal)

    outcomes = guard1.ingest_certificates_batch(certificates=(certs[-1], *certs[:-1]))
    assert all(item.accepted for item in outcomes)
    fallbacks = guard1.finalize_timeouts(now_ms=1051)
    assert len(fallbacks) == 1
    assert fallbacks[0].code == "fallback_finalized"

    profile = HelperAssemblyProfile(helper_mode_enabled=True, require_serial_equivalence=True, fail_closed_on_helper_error=True)
    expected_lanes = tuple(sorted(plan.lane_id for plan in helper_lanes))
    snapshot1 = build_helper_restart_snapshot(
        profile=profile,
        context=dispatch_context(plan_id=plan_id),
        lane_plans=lane_plans,
        lane_results_by_id=lane_results_by_id,
        journal=journal,
        helper_pubkeys=helper_pubkeys,
        helper_timeout_ms=50,
        serial_equivalence_fn=lambda candidates: tuple(item.lane_id for item in candidates) == expected_lanes,
    )
    assert snapshot1.assembly_accepted is True
    assert snapshot1.assembly_mode == "helper_assisted"
    assert snapshot1.unresolved_lanes == ()
    assert snapshot1.journal_plan_id == plan_id
    assert snapshot1.plan_id

    orchestrator2 = HelperProposalOrchestrator(
        context=dispatch_context(plan_id=plan_id),
        lane_plans=lane_plans,
        helper_pubkeys=helper_pubkeys,
        journal=journal,
        helper_timeout_ms=50,
    )
    guard2 = HelperReplayGuard(orchestrator=orchestrator2, journal=journal)
    assert tuple(sorted(guard2.resolved_lanes())) == expected_lanes
    reversed_results = {lane_id: lane_results_by_id[lane_id] for lane_id in reversed(tuple(lane_results_by_id.keys()))}
    snapshot2 = build_helper_restart_snapshot(
        profile=profile,
        context=dispatch_context(plan_id=plan_id),
        lane_plans=lane_plans,
        lane_results_by_id=reversed_results,
        journal=journal,
        helper_pubkeys=helper_pubkeys,
        helper_timeout_ms=50,
        serial_equivalence_fn=lambda candidates: tuple(item.lane_id for item in candidates) == expected_lanes,
    )
    assert snapshot2.to_json() == snapshot1.to_json()
    assert snapshot2.snapshot_hash() == snapshot1.snapshot_hash()


def test_helper_restart_snapshot_keeps_fail_closed_vs_serial_fallback_stable_on_merge_conflict_batch8(tmp_path) -> None:
    lane_plans, plan_id = lane_setup(txs=MULTILANE_TXS)
    helper_lanes, _accepted_lanes, _fallback_lane, lane_results_by_id, helper_pubkeys, certs = _materialize_lane_results(
        lane_plans=lane_plans,
        plan_id=plan_id,
        shared_key="shared/conflict",
    )

    journal = HelperLaneJournal(str(tmp_path / "helper-conflict.jsonl"))
    orchestrator1 = HelperProposalOrchestrator(
        context=dispatch_context(plan_id=plan_id),
        lane_plans=lane_plans,
        helper_pubkeys=helper_pubkeys,
        journal=journal,
        helper_timeout_ms=50,
    )
    orchestrator1.start_collection(started_ms=1000)
    guard1 = HelperReplayGuard(orchestrator=orchestrator1, journal=journal)
    outcomes = guard1.ingest_certificates_batch(certificates=(certs[1], certs[0]))
    assert all(item.accepted for item in outcomes)
    fallbacks = guard1.finalize_timeouts(now_ms=1051)
    assert len(fallbacks) == 1

    strict_profile = HelperAssemblyProfile(helper_mode_enabled=True, require_serial_equivalence=True, fail_closed_on_helper_error=True)
    strict_snapshot = build_helper_restart_snapshot(
        profile=strict_profile,
        context=dispatch_context(plan_id=plan_id),
        lane_plans=lane_plans,
        lane_results_by_id=lane_results_by_id,
        journal=journal,
        helper_pubkeys=helper_pubkeys,
        helper_timeout_ms=50,
        serial_equivalence_fn=lambda candidates: True,
    )
    assert strict_snapshot.assembly_accepted is False
    assert strict_snapshot.assembly_mode == "helper_assisted"
    assert strict_snapshot.assembly_code == "merge_conflict:shared/conflict"

    orchestrator2 = HelperProposalOrchestrator(
        context=dispatch_context(plan_id=plan_id),
        lane_plans=lane_plans,
        helper_pubkeys=helper_pubkeys,
        journal=journal,
        helper_timeout_ms=50,
    )
    strict_restart = build_helper_restart_snapshot(
        profile=strict_profile,
        context=dispatch_context(plan_id=plan_id),
        lane_plans=lane_plans,
        lane_results_by_id={lane_id: lane_results_by_id[lane_id] for lane_id in reversed(tuple(lane_results_by_id.keys()))},
        journal=journal,
        helper_pubkeys=helper_pubkeys,
        helper_timeout_ms=50,
        serial_equivalence_fn=lambda candidates: True,
    )
    assert strict_restart.to_json() == strict_snapshot.to_json()

    permissive_profile = HelperAssemblyProfile(helper_mode_enabled=True, require_serial_equivalence=True, fail_closed_on_helper_error=False)
    permissive_snapshot = build_helper_restart_snapshot(
        profile=permissive_profile,
        context=dispatch_context(plan_id=plan_id),
        lane_plans=lane_plans,
        lane_results_by_id=lane_results_by_id,
        journal=journal,
        helper_pubkeys=helper_pubkeys,
        helper_timeout_ms=50,
        serial_equivalence_fn=lambda candidates: True,
    )
    assert permissive_snapshot.assembly_accepted is True
    assert permissive_snapshot.assembly_mode == "serial_only"
    assert permissive_snapshot.assembly_code == "serial_fallback:merge_conflict:shared/conflict"
