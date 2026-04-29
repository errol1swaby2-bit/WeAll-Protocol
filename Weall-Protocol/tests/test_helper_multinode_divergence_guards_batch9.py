from __future__ import annotations

from pathlib import Path

from helper_audit_testkit import dispatch_context, lane_setup, signed_lane_certificate
from weall.runtime.helper_assembly_gate import HelperAssemblyProfile
from weall.runtime.helper_lane_journal import HelperLaneJournal
from weall.runtime.helper_restart_replay import build_helper_restart_snapshot
from weall.runtime.parallel_execution import canonical_lane_plan_fingerprint, plan_parallel_execution, verify_lane_plan_equivalence


def _tx(tx_id: str, tx_type: str, prefixes: list[str]) -> dict:
    return {"tx_id": tx_id, "tx_type": tx_type, "state_prefixes": prefixes}


def _canonical_ingress(txs: list[dict]) -> list[dict]:
    return sorted((dict(tx) for tx in txs), key=lambda item: str(item["tx_id"]))


def test_same_block_different_ingress_order_produces_same_lane_plan_batch9() -> None:
    txs = [
        _tx("t3", "SOCIAL_FOLLOW", ["social:follow:@alice:@bob"]),
        _tx("t1", "CONTENT_CREATE", ["content:post:1"]),
        _tx("t4", "NOTIFICATION_SUBSCRIBE", ["notify:@alice:dm"]),
        _tx("t2", "IDENTITY_UPDATE", ["identity:user:alice"]),
    ]
    left = plan_parallel_execution(
        txs=_canonical_ingress(txs),
        validators=["v4", "v2", "v1", "v3"],
        validator_set_hash="vh-1",
        view=19,
        leader_id="v1",
    )
    right = plan_parallel_execution(
        txs=_canonical_ingress(list(reversed(txs))),
        validators=["v2", "v3", "v4", "v1"],
        validator_set_hash="vh-1",
        view=19,
        leader_id="v1",
    )
    ok, reason = verify_lane_plan_equivalence(local_lane_plans=left, remote_lane_plans=right)
    assert ok is True
    assert reason == "ok"
    assert canonical_lane_plan_fingerprint(left) == canonical_lane_plan_fingerprint(right)
    assert tuple((plan.lane_id, plan.helper_id, plan.tx_ids) for plan in left) == tuple(
        (plan.lane_id, plan.helper_id, plan.tx_ids) for plan in right
    )



def test_validator_set_order_does_not_destabilize_multinode_plan_shape_batch9() -> None:
    txs = [
        _tx("t1", "CONTENT_CREATE", ["content:post:1"]),
        _tx("t2", "CONTENT_CREATE", ["content:post:2"]),
        _tx("t3", "GROUP_MEMBERSHIP_REQUEST", ["group:member:g1:@alice"]),
    ]
    left = plan_parallel_execution(
        txs=list(txs),
        validators=["v4", "v2", "v1", "v3"],
        validator_set_hash="vh-2",
        view=8,
        leader_id="v1",
    )
    right = plan_parallel_execution(
        txs=list(txs),
        validators=["v1", "v2", "v3", "v4"],
        validator_set_hash="vh-2",
        view=8,
        leader_id="v1",
    )
    assert canonical_lane_plan_fingerprint(left) == canonical_lane_plan_fingerprint(right)
    assert tuple((plan.lane_id, plan.helper_id, plan.tx_ids) for plan in left) == tuple(
        (plan.lane_id, plan.helper_id, plan.tx_ids) for plan in right
    )



def test_restart_snapshot_is_stable_across_different_recovery_points_batch9(tmp_path: Path) -> None:
    txs = [
        _tx("c1", "CONTENT_CREATE", ["content:post:1"]),
        _tx("i1", "IDENTITY_UPDATE", ["identity:user:alice"]),
    ]
    lane_plans, plan_id = lane_setup(txs=txs, validators=("v1", "v2", "v3", "v4"), view=11, leader_id="v1")
    helper_lanes = [plan for plan in lane_plans if str(plan.helper_id or "")]
    assert helper_lanes

    lane_results_by_id = {
        str(plan.lane_id): {
            "receipts": tuple({"tx_id": tx_id, "status": "ok", "lane_id": str(plan.lane_id)} for tx_id in plan.tx_ids),
            "state_delta": {f"delta:{plan.lane_id}": list(plan.tx_ids)},
            "tx_ids": tuple(plan.tx_ids),
            "plan_id": plan_id,
        }
        for plan in lane_plans
    }

    primary_journal = HelperLaneJournal(str(tmp_path / "primary.journal"))
    secondary_journal = HelperLaneJournal(str(tmp_path / "secondary.journal"))

    cert, _pub = signed_lane_certificate(lane_plan=helper_lanes[0], seed_byte=31, plan_id=plan_id, receipts_root="r1")

    primary_journal.append_plan(
        plan_id=plan_id,
        lanes=tuple({"lane_id": str(plan.lane_id), "helper_id": str(plan.helper_id or ""), "tx_ids": list(plan.tx_ids)} for plan in lane_plans),
    )
    primary_journal.append({
        "kind": "helper_finalized",
        "lane_id": str(helper_lanes[0].lane_id),
        "helper_id": str(helper_lanes[0].helper_id or ""),
        "certificate": cert.to_json(),
        "plan_id": plan_id,
    })
    for lane in helper_lanes[1:]:
        primary_journal.append_fallback(plan_id=plan_id, lane_id=str(lane.lane_id), helper_id=str(lane.helper_id or ""))

    secondary_journal.append_plan(
        plan_id=plan_id,
        lanes=tuple({"lane_id": str(plan.lane_id), "helper_id": str(plan.helper_id or ""), "tx_ids": list(plan.tx_ids)} for plan in lane_plans),
    )
    secondary_journal.append_receipt_reject(
        plan_id=plan_id,
        lane_id=str(helper_lanes[0].lane_id),
        helper_id=str(helper_lanes[0].helper_id or ""),
        receipt_fingerprint="noise",
        reason="duplicate_certificate",
    )
    for lane in helper_lanes[1:]:
        secondary_journal.append_fallback(plan_id=plan_id, lane_id=str(lane.lane_id), helper_id=str(lane.helper_id or ""))
    secondary_journal.append({
        "kind": "helper_finalized",
        "lane_id": str(helper_lanes[0].lane_id),
        "helper_id": str(helper_lanes[0].helper_id or ""),
        "certificate": cert.to_json(),
        "plan_id": plan_id,
    })

    profile = HelperAssemblyProfile(helper_mode_enabled=True, require_serial_equivalence=False, fail_closed_on_helper_error=False)
    ctx = dispatch_context(plan_id=plan_id)

    left = build_helper_restart_snapshot(
        profile=profile,
        context=ctx,
        lane_plans=lane_plans,
        lane_results_by_id=lane_results_by_id,
        journal=primary_journal,
        helper_pubkeys={},
    )
    right = build_helper_restart_snapshot(
        profile=profile,
        context=ctx,
        lane_plans=lane_plans,
        lane_results_by_id=lane_results_by_id,
        journal=secondary_journal,
        helper_pubkeys={},
    )

    assert left.snapshot_hash() == right.snapshot_hash()
    assert left.plan_id == right.plan_id
    assert left.journal_plan_id == right.journal_plan_id == plan_id
    assert left.finalized_modes == right.finalized_modes
