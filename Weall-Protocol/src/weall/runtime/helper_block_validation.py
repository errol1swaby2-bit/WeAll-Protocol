from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from weall.runtime.helper_certificates import (
    ensure_helper_execution_certificate,
    verify_helper_certificate_signature,
)
from weall.runtime.helper_reputation import (
    apply_helper_quarantine_to_lane_plans,
    summarize_helper_reputation_state,
)
from weall.runtime.parallel_execution import (
    canonical_lane_plan_fingerprint,
    plan_parallel_execution,
    verify_block_helper_plan_metadata,
    verify_helper_certificate,
)

Json = dict[str, Any]


def _root_map(state: Mapping[str, Any], key: str) -> Json:
    raw = state.get(str(key))
    return dict(raw) if isinstance(raw, Mapping) else {}


def validate_received_helper_execution(
    *,
    block: Mapping[str, Any],
    state: Mapping[str, Any],
    chain_id: str,
    validators: list[str],
    validator_pubkeys: Mapping[str, str],
    validator_epoch: int,
    validator_set_hash: str,
) -> tuple[bool, str]:
    """Independently bind advertised helper metadata to canonical local inputs.

    Self-consistency of remote metadata is necessary but insufficient. This routine
    reconstructs the helper plan from the received canonical transaction order and
    the receiver's root-bound pre-state, then cryptographically reverifies every
    certificate that the proposer claims was accepted.
    """
    helper_execution = block.get("helper_execution")
    if helper_execution is None:
        return True, "ok"
    if not isinstance(helper_execution, Mapping):
        return False, "helper_execution_must_be_object"

    advertised_plan_id = str(helper_execution.get("plan_id") or "").strip()
    ok, reason = verify_block_helper_plan_metadata(
        helper_execution=helper_execution,
        expected_plan_id=advertised_plan_id,
    )
    if not ok:
        return False, str(reason)

    block_view = int(block.get("view") or block.get("bft_view") or 0)
    header = block.get("header") if isinstance(block.get("header"), Mapping) else {}
    if block_view == 0:
        block_view = int(header.get("view") or header.get("bft_view") or 0)
    leader_id = str(
        block.get("proposer")
        or block.get("node_id")
        or header.get("proposer")
        or header.get("node_id")
        or ""
    ).strip()
    block_height = int(block.get("height") or header.get("height") or 0)
    block_ts_ms = int(block.get("block_ts_ms") or header.get("block_ts_ms") or 0)

    if int(helper_execution.get("view") or 0) != block_view:
        return False, "helper_execution_view_mismatch"
    if int(helper_execution.get("validator_epoch") or 0) != int(validator_epoch):
        return False, "helper_execution_validator_epoch_mismatch"
    if str(helper_execution.get("validator_set_hash") or "") != str(validator_set_hash):
        return False, "helper_execution_validator_set_hash_mismatch"
    coordinator_id = str(helper_execution.get("coordinator_id") or "").strip()
    if not leader_id:
        # Non-BFT/dev helper candidates do not carry a top-level proposer field.
        # The locally built execution manifest still commits to coordinator_id,
        # so use that committed value as the deterministic planning leader.
        leader_id = coordinator_id
    if coordinator_id and leader_id and coordinator_id != leader_id:
        return False, "helper_execution_coordinator_mismatch"

    txs = block.get("txs")
    if not isinstance(txs, list):
        return False, "helper_execution_block_txs_missing"

    helper_reputation_state = _root_map(state, "helper_reputation")
    helper_capacity_by_helper = _root_map(state, "helper_capacity_by_helper")
    helper_capabilities_by_helper = _root_map(state, "helper_capabilities_by_helper")
    reputation_summary = summarize_helper_reputation_state(
        helper_reputation_state=helper_reputation_state,
        now_ms=block_ts_ms,
    )
    local_plans = plan_parallel_execution(
        txs=[dict(tx) for tx in txs if isinstance(tx, Mapping)],
        validators=list(validators or []),
        validator_set_hash=str(validator_set_hash),
        view=int(block_view),
        leader_id=str(leader_id),
        state_snapshot_metadata={
            "validator_epoch": int(validator_epoch),
            "quarantined_helper_ids": list(reputation_summary.get("quarantined_helper_ids") or []),
            "helper_capacity_by_helper": dict(helper_capacity_by_helper),
            "helper_capabilities_by_helper": dict(helper_capabilities_by_helper),
            "helper_planning_inputs_source": "state_root",
            "allow_helper_overcommit": True,
        },
    )
    local_plans = apply_helper_quarantine_to_lane_plans(
        local_plans,
        helper_reputation_state=helper_reputation_state,
        now_ms=block_ts_ms,
    )
    local_plan_id = canonical_lane_plan_fingerprint(local_plans)
    if not local_plan_id or local_plan_id != advertised_plan_id:
        return False, "helper_execution_canonical_plan_mismatch"

    local_by_lane = {str(plan.lane_id): plan for plan in local_plans}
    manifest_hash = str(helper_execution.get("manifest_hash") or "").strip()
    seen_accepted_lanes: set[str] = set()
    for row in list(helper_execution.get("accepted_certificates") or []):
        if not isinstance(row, Mapping):
            return False, "helper_execution_certificate_bad_shape"
        if not bool(row.get("accepted")):
            continue
        lane_id = str(row.get("lane_id") or "").strip()
        if not lane_id or lane_id in seen_accepted_lanes:
            return False, "helper_execution_accepted_lane_duplicate"
        seen_accepted_lanes.add(lane_id)
        plan = local_by_lane.get(lane_id)
        if plan is None:
            return False, "helper_execution_certificate_unknown_lane"
        raw_cert = row.get("certificate")
        if not isinstance(raw_cert, Mapping):
            return False, "helper_execution_full_certificate_missing"
        try:
            cert = ensure_helper_execution_certificate(raw_cert)
        except Exception:
            return False, "helper_execution_certificate_bad_shape"
        expected_helper_id = str(plan.helper_id or "")
        if not expected_helper_id:
            return False, "helper_execution_certificate_for_serial_lane"
        if str(row.get("helper_id") or "") != expected_helper_id:
            return False, "helper_execution_certificate_helper_summary_mismatch"
        ok_cert, cert_reason = verify_helper_certificate(
            cert=cert,
            lane_plan=plan,
            expected_helper_id=expected_helper_id,
            chain_id=str(chain_id),
            block_height=int(block_height),
            view=int(block_view),
            leader_id=str(leader_id),
            validator_epoch=int(validator_epoch),
            validator_set_hash=str(validator_set_hash),
            manifest_hash=str(manifest_hash),
            require_internal_consistency=True,
            plan_id=str(local_plan_id),
            require_plan_id_match=True,
            require_manifest_hash_match=bool(manifest_hash),
            enforce_tx_order_hash=True,
            enforce_namespace_hash=True,
        )
        if not ok_cert:
            return False, f"helper_execution_certificate_invalid:{cert_reason}"
        pubkey = str(validator_pubkeys.get(expected_helper_id) or "").strip()
        if not pubkey:
            return False, "helper_execution_helper_pubkey_missing"
        if not verify_helper_certificate_signature(cert, helper_pubkey=pubkey):
            return False, "helper_execution_certificate_signature_invalid"

    return True, "ok"


__all__ = ["validate_received_helper_execution"]
