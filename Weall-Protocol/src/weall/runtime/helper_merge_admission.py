from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
import json
from typing import Any, Callable, Mapping, Sequence

from weall.runtime.helper_proposal_orchestrator import HelperLaneResolution


Json = dict[str, Any]


def _canon_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _sha256_hex(value: Any) -> str:
    if not isinstance(value, str):
        value = _canon_json(value)
    return sha256(value.encode("utf-8")).hexdigest()


def canonical_receipts_root(receipts: Sequence[Mapping[str, Any]]) -> str:
    return _sha256_hex([dict(r) for r in receipts])


def canonical_state_delta_hash(delta: Mapping[str, Any]) -> str:
    return _sha256_hex(dict(delta))


def canonical_lane_plan_id(lane_plan_by_id: Mapping[str, Any] | None) -> str:
    normalized: list[Json] = []
    for lane_id, plan in sorted(dict(lane_plan_by_id or {}).items()):
        tx_ids = tuple(str(v) for v in getattr(plan, "tx_ids", ()) or ())
        helper_id = str(getattr(plan, "helper_id", "") or "")
        normalized.append({"lane_id": str(lane_id), "helper_id": helper_id, "tx_ids": list(tx_ids)})
    if not normalized:
        return ""
    return _sha256_hex(normalized)


@dataclass(frozen=True, slots=True)
class HelperMergeCandidate:
    lane_id: str
    helper_id: str
    mode: str  # helper | fallback
    receipts: tuple[Json, ...]
    state_delta: Json
    receipts_root: str
    state_delta_hash: str
    tx_ids: tuple[str, ...] = ()
    plan_id: str = ""

    @classmethod
    def from_resolution(
        cls,
        resolution: HelperLaneResolution,
        *,
        receipts: Sequence[Mapping[str, Any]],
        state_delta: Mapping[str, Any],
        tx_ids: Sequence[str] = (),
        plan_id: str = "",
    ) -> "HelperMergeCandidate":
        receipts_tuple = tuple(dict(r) for r in receipts)
        delta_dict = dict(state_delta)
        tx_ids_tuple = tuple(str(v) for v in tx_ids)
        if not tx_ids_tuple:
            tx_ids_tuple = tuple(str(r.get("tx_id") or "") for r in receipts_tuple)
        return cls(
            lane_id=str(resolution.lane_id),
            helper_id=str(resolution.helper_id),
            mode=str(resolution.mode),
            receipts=receipts_tuple,
            state_delta=delta_dict,
            receipts_root=canonical_receipts_root(receipts_tuple),
            state_delta_hash=canonical_state_delta_hash(delta_dict),
            tx_ids=tx_ids_tuple,
            plan_id=str(plan_id or ""),
        )


@dataclass(frozen=True, slots=True)
class HelperMergeAdmissionDecision:
    accepted: bool
    code: str
    receipts_root: str
    merged_state_delta_hash: str
    lane_count: int
    plan_id: str = ""
    failure_stage: str = ""
    lane_id: str = ""
    detail: str = ""
    conflicting_state_keys: tuple[str, ...] = ()
    conflicting_tx_ids: tuple[str, ...] = ()

    def to_json(self) -> Json:
        return {
            "accepted": bool(self.accepted),
            "code": str(self.code),
            "receipts_root": str(self.receipts_root),
            "merged_state_delta_hash": str(self.merged_state_delta_hash),
            "lane_count": int(self.lane_count),
            "plan_id": str(self.plan_id),
            "failure_stage": str(self.failure_stage),
            "lane_id": str(self.lane_id),
            "detail": str(self.detail),
            "conflicting_state_keys": list(self.conflicting_state_keys),
            "conflicting_tx_ids": list(self.conflicting_tx_ids),
        }


def merge_state_deltas(
    candidates: Sequence[HelperMergeCandidate],
) -> Json:
    merged: Json = {}
    touched: set[str] = set()

    for candidate in sorted(candidates, key=lambda item: item.lane_id):
        for key, value in candidate.state_delta.items():
            skey = str(key)
            if skey in touched:
                raise ValueError(("merge_conflict", skey, candidate.lane_id))
            touched.add(skey)
            merged[skey] = value
    return merged


def helper_receipts_from_candidates(
    candidates: Sequence[HelperMergeCandidate],
) -> tuple[Json, ...]:
    ordered: list[Json] = []
    for candidate in sorted(candidates, key=lambda item: item.lane_id):
        ordered.extend(dict(r) for r in candidate.receipts)
    return tuple(ordered)


def admit_helper_merge(
    *,
    resolutions: Sequence[HelperLaneResolution],
    lane_results_by_id: Mapping[str, Mapping[str, Any]],
    serial_equivalence_fn: Callable[[tuple[HelperMergeCandidate, ...]], bool] | None = None,
    require_all_lanes_resolved: bool = True,
    lane_plan_by_id: Mapping[str, Any] | None = None,
    expected_plan_id: str = "",
) -> HelperMergeAdmissionDecision:
    if not resolutions and require_all_lanes_resolved:
        return HelperMergeAdmissionDecision(
            accepted=False,
            code="no_lane_resolutions",
            receipts_root="",
            merged_state_delta_hash="",
            lane_count=0,
            plan_id=str(expected_plan_id or canonical_lane_plan_id(lane_plan_by_id)),
            failure_stage="resolution",
            lane_id="",
            detail="no helper lane resolutions were available",
        )

    effective_plan_id = str(expected_plan_id or canonical_lane_plan_id(lane_plan_by_id))
    candidates: list[HelperMergeCandidate] = []
    seen_lane_ids: set[str] = set()
    seen_candidate_tx_ids: set[str] = set()
    seen_receipt_tx_ids: set[str] = set()

    for resolution in sorted(resolutions, key=lambda item: item.lane_id):
        lane_id = str(resolution.lane_id or "")
        if not lane_id:
            return HelperMergeAdmissionDecision(False, "empty_lane_id", "", "", len(candidates), effective_plan_id, "resolution", lane_id, "empty lane id")
        if lane_id in seen_lane_ids:
            return HelperMergeAdmissionDecision(False, "duplicate_lane_resolution", "", "", len(candidates), effective_plan_id, "resolution", lane_id, "duplicate lane resolution")
        seen_lane_ids.add(lane_id)

        lane_result = lane_results_by_id.get(lane_id)
        if not isinstance(lane_result, dict):
            return HelperMergeAdmissionDecision(False, "missing_lane_result", "", "", len(candidates), effective_plan_id, "lane_result", lane_id, "missing lane result")
        receipts = lane_result.get("receipts")
        state_delta = lane_result.get("state_delta")
        if not isinstance(receipts, (list, tuple)) or not isinstance(state_delta, dict):
            return HelperMergeAdmissionDecision(False, "malformed_lane_result", "", "", len(candidates), effective_plan_id, "lane_result", lane_id, "malformed lane result")

        plan = None if lane_plan_by_id is None else lane_plan_by_id.get(lane_id)
        expected_tx_ids = tuple(str(v) for v in list(lane_result.get("tx_ids") or ()) if str(v))
        if not expected_tx_ids and plan is not None:
            expected_tx_ids = tuple(str(v) for v in getattr(plan, "tx_ids", ()) or ())
        observed_tx_ids = tuple(str(r.get("tx_id") or "") for r in receipts)
        if expected_tx_ids and observed_tx_ids != expected_tx_ids:
            return HelperMergeAdmissionDecision(False, "lane_tx_ids_mismatch", "", "", len(candidates), effective_plan_id, "lane_result", lane_id, "receipt tx order did not match expected lane tx ids", (), expected_tx_ids or observed_tx_ids)
        if observed_tx_ids and len(set(observed_tx_ids)) != len(observed_tx_ids):
            return HelperMergeAdmissionDecision(False, "duplicate_lane_receipt_tx_id", "", "", len(candidates), effective_plan_id, "lane_result", lane_id, "duplicate receipt tx id within lane", (), tuple(sorted(observed_tx_ids)))
        if expected_tx_ids and len(set(expected_tx_ids)) != len(expected_tx_ids):
            return HelperMergeAdmissionDecision(False, "duplicate_lane_tx_id", "", "", len(candidates), effective_plan_id, "lane_result", lane_id, "duplicate tx id metadata within lane", (), tuple(sorted(expected_tx_ids)))
        if expected_tx_ids:
            overlap = tuple(sorted(tx_id for tx_id in expected_tx_ids if tx_id in seen_candidate_tx_ids))
            if overlap:
                return HelperMergeAdmissionDecision(False, "cross_lane_tx_id_conflict", "", "", len(candidates), effective_plan_id, "lane_result", lane_id, "tx id overlap across helper lanes", (), overlap)
            seen_candidate_tx_ids.update(expected_tx_ids)
        if observed_tx_ids:
            receipt_overlap = tuple(sorted(tx_id for tx_id in observed_tx_ids if tx_id in seen_receipt_tx_ids))
            if receipt_overlap:
                return HelperMergeAdmissionDecision(False, "cross_lane_receipt_tx_id_conflict", "", "", len(candidates), effective_plan_id, "lane_result", lane_id, "receipt tx id overlap across helper lanes", (), receipt_overlap)
            seen_receipt_tx_ids.update(observed_tx_ids)

        lane_result_plan_id = str(lane_result.get("plan_id") or "")
        if effective_plan_id and lane_result_plan_id and lane_result_plan_id != effective_plan_id:
            return HelperMergeAdmissionDecision(False, "plan_id_mismatch", "", "", len(candidates), effective_plan_id, "plan_binding", lane_id, "lane result plan id mismatch")

        candidate = HelperMergeCandidate.from_resolution(
            resolution,
            receipts=tuple(dict(r) for r in receipts),
            state_delta=dict(state_delta),
            tx_ids=expected_tx_ids,
            plan_id=effective_plan_id,
        )

        cert = resolution.certificate
        if cert is not None:
            cert_plan_id = str(getattr(cert, "plan_id", "") or "")
            if effective_plan_id and cert_plan_id and cert_plan_id != effective_plan_id:
                return HelperMergeAdmissionDecision(False, "certificate_plan_id_mismatch", "", "", len(candidates), effective_plan_id, "certificate", lane_id, "certificate plan id mismatch")
            cert_receipts_root = str(getattr(cert, "receipts_root", "") or "")
            cert_delta_hash = str(getattr(cert, "lane_delta_hash", "") or "")
            cert_tx_ids = tuple(str(v) for v in getattr(cert, "tx_ids", ()) or ())
            if cert_receipts_root and cert_receipts_root != candidate.receipts_root:
                return HelperMergeAdmissionDecision(False, "receipts_root_mismatch", "", "", len(candidates), effective_plan_id, "certificate", lane_id, "certificate receipts root mismatch")
            if cert_delta_hash and cert_delta_hash != candidate.state_delta_hash:
                return HelperMergeAdmissionDecision(False, "state_delta_hash_mismatch", "", "", len(candidates), effective_plan_id, "certificate", lane_id, "certificate state delta hash mismatch")
            if cert_tx_ids and candidate.tx_ids and cert_tx_ids != candidate.tx_ids:
                return HelperMergeAdmissionDecision(False, "certificate_tx_ids_mismatch", "", "", len(candidates), effective_plan_id, "certificate", lane_id, "certificate tx ids mismatch", (), cert_tx_ids or candidate.tx_ids)

        candidates.append(candidate)

    if lane_plan_by_id is not None:
        expected_lanes = tuple(sorted(str(k) for k in lane_plan_by_id.keys()))
        resolved_lanes = tuple(sorted(seen_lane_ids))
        if require_all_lanes_resolved and expected_lanes != resolved_lanes:
            return HelperMergeAdmissionDecision(False, "lane_resolution_set_mismatch", "", "", len(candidates), effective_plan_id, "resolution", "", "resolved helper lanes did not match lane plan")

    try:
        merged_delta = merge_state_deltas(tuple(candidates))
    except ValueError as exc:
        payload = exc.args[0] if exc.args else ""
        if isinstance(payload, tuple) and len(payload) >= 3 and str(payload[0]) == "merge_conflict":
            return HelperMergeAdmissionDecision(
                False,
                "merge_conflict:" + str(payload[1]),
                "",
                "",
                len(candidates),
                effective_plan_id,
                "merge",
                str(payload[2]),
                "state delta key written by more than one helper lane",
                (str(payload[1]),),
                (),
            )
        return HelperMergeAdmissionDecision(False, str(exc), "", "", len(candidates), effective_plan_id, "merge", "", str(exc))

    if serial_equivalence_fn is not None:
        ok = bool(serial_equivalence_fn(tuple(candidates)))
        if not ok:
            return HelperMergeAdmissionDecision(False, "serial_equivalence_failed", "", "", len(candidates), effective_plan_id, "serial_equivalence", "", "serial equivalence function rejected helper merge")

    ordered_receipts = helper_receipts_from_candidates(tuple(candidates))
    return HelperMergeAdmissionDecision(
        accepted=True,
        code="accepted",
        receipts_root=canonical_receipts_root(ordered_receipts),
        merged_state_delta_hash=canonical_state_delta_hash(merged_delta),
        lane_count=len(candidates),
        plan_id=effective_plan_id,
        failure_stage="",
        lane_id="",
        detail="merge accepted",
    )
