from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Any, Mapping, Sequence

from weall.runtime.helper_certificates import hash_receipts, hash_state_delta_ops
from weall.runtime.parallel_execution import LanePlan, canonical_lane_plan_fingerprint

Json = dict[str, Any]


def _canon_json(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


@dataclass(frozen=True, slots=True)
class LaneAuditDecision:
    lane_id: str
    helper_id: str
    selected: bool
    reason: str
    risk_class: str
    tx_ids: tuple[str, ...]
    plan_id: str = ""

    def to_json(self) -> Json:
        return {
            "lane_id": self.lane_id,
            "helper_id": self.helper_id,
            "selected": bool(self.selected),
            "reason": self.reason,
            "risk_class": self.risk_class,
            "tx_ids": list(self.tx_ids),
            "plan_id": self.plan_id,
        }


@dataclass(frozen=True, slots=True)
class LaneAuditResult:
    lane_id: str
    helper_id: str
    checked: bool
    receipts_match: bool
    state_delta_match: bool | None
    expected_receipts_root: str
    helper_receipts_root: str
    expected_state_delta_hash: str
    helper_state_delta_hash: str
    fraud_suspected: bool
    reason: str
    tx_ids: tuple[str, ...]
    plan_id: str = ""

    def to_json(self) -> Json:
        return {
            "lane_id": self.lane_id,
            "helper_id": self.helper_id,
            "checked": bool(self.checked),
            "receipts_match": bool(self.receipts_match),
            "state_delta_match": self.state_delta_match,
            "expected_receipts_root": self.expected_receipts_root,
            "helper_receipts_root": self.helper_receipts_root,
            "expected_state_delta_hash": self.expected_state_delta_hash,
            "helper_state_delta_hash": self.helper_state_delta_hash,
            "fraud_suspected": bool(self.fraud_suspected),
            "reason": self.reason,
            "tx_ids": list(self.tx_ids),
            "plan_id": self.plan_id,
        }


HIGH_RISK_PREFIXES = (
    "economics:",
    "treasury:",
    "governance:",
    "identity:",
    "poh:",
    "roles:",
    "group:",
)


def _lane_risk_class(lane: LanePlan) -> str:
    prefixes = tuple(str(p).strip().lower() for p in lane.namespace_prefixes if str(p).strip())
    if any(prefix.startswith(HIGH_RISK_PREFIXES) for prefix in prefixes):
        return "high"
    if len(tuple(lane.tx_ids)) >= 8:
        return "high"
    if len(tuple(lane.tx_ids)) >= 4:
        return "medium"
    return "standard"


def _deterministic_percent(*, manifest_hash: str, lane_id: str, plan_id: str = "") -> int:
    material = _canon_json({"manifest_hash": str(manifest_hash), "lane_id": str(lane_id), "plan_id": str(plan_id or "")})
    digest = hashlib.sha256(material).digest()
    return int.from_bytes(digest[:2], "big") % 100


def build_lane_audit_plan(
    *,
    lane_plans: Sequence[LanePlan],
    manifest_hash: str,
    sample_percent: int = 15,
    always_audit_high_risk: bool = True,
    require_helper_lanes_only: bool = True,
    plan_id: str = "",
) -> tuple[LaneAuditDecision, ...]:
    pct = max(0, min(100, int(sample_percent)))
    effective_plan_id = str(plan_id or canonical_lane_plan_fingerprint(tuple(lane_plans or ())))
    decisions: list[LaneAuditDecision] = []
    for lane in list(lane_plans or []):
        helper_id = str(lane.helper_id or "")
        if require_helper_lanes_only and not helper_id:
            continue
        risk_class = _lane_risk_class(lane)
        selected = False
        reason = "sample_skipped"
        if always_audit_high_risk and risk_class == "high":
            selected = True
            reason = "high_risk_lane"
        elif pct > 0 and _deterministic_percent(manifest_hash=str(manifest_hash), lane_id=str(lane.lane_id), plan_id=effective_plan_id) < pct:
            selected = True
            reason = "deterministic_sample"
        decisions.append(
            LaneAuditDecision(
                lane_id=str(lane.lane_id),
                helper_id=helper_id,
                selected=selected,
                reason=reason,
                risk_class=risk_class,
                tx_ids=tuple(str(x) for x in lane.tx_ids),
                plan_id=effective_plan_id,
            )
        )
    decisions.sort(key=lambda item: item.lane_id)
    return tuple(decisions)


def evaluate_lane_audit_plan(
    *,
    audit_plan: Sequence[LaneAuditDecision],
    canonical_receipts_by_lane: Mapping[str, Sequence[Mapping[str, Any]]] | None = None,
    helper_receipts_by_lane: Mapping[str, Sequence[Mapping[str, Any]]] | None = None,
    canonical_state_deltas_by_lane: Mapping[str, Sequence[Mapping[str, Any]]] | None = None,
    helper_state_deltas_by_lane: Mapping[str, Sequence[Mapping[str, Any]]] | None = None,
    expected_plan_id: str = "",
) -> tuple[LaneAuditResult, ...]:
    results: list[LaneAuditResult] = []
    canonical_receipts_by_lane = dict(canonical_receipts_by_lane or {})
    helper_receipts_by_lane = dict(helper_receipts_by_lane or {})
    canonical_state_deltas_by_lane = dict(canonical_state_deltas_by_lane or {})
    helper_state_deltas_by_lane = dict(helper_state_deltas_by_lane or {})
    effective_plan_id = str(expected_plan_id or "")
    for decision in list(audit_plan or []):
        if not decision.selected:
            continue
        decision_plan_id = str(decision.plan_id or "")
        lane_plan_id = str(effective_plan_id or decision_plan_id)
        canonical_receipts = [dict(item) for item in list(canonical_receipts_by_lane.get(decision.lane_id) or []) if isinstance(item, Mapping)]
        helper_receipts = [dict(item) for item in list(helper_receipts_by_lane.get(decision.lane_id) or []) if isinstance(item, Mapping)]
        expected_receipts_root = hash_receipts(canonical_receipts)
        helper_receipts_root = hash_receipts(helper_receipts)
        receipts_match = expected_receipts_root == helper_receipts_root

        expected_state_delta_hash = ""
        helper_state_delta_hash = ""
        state_delta_match: bool | None = None
        if decision.lane_id in canonical_state_deltas_by_lane or decision.lane_id in helper_state_deltas_by_lane:
            expected_state_delta_hash = hash_state_delta_ops(
                list(canonical_state_deltas_by_lane.get(decision.lane_id) or [])
            )
            helper_state_delta_hash = hash_state_delta_ops(
                list(helper_state_deltas_by_lane.get(decision.lane_id) or [])
            )
            state_delta_match = expected_state_delta_hash == helper_state_delta_hash

        fraud_suspected = (not receipts_match) or (state_delta_match is False)
        if effective_plan_id and decision_plan_id and decision_plan_id != effective_plan_id:
            fraud_suspected = True
            reason = "plan_id_mismatch"
        elif fraud_suspected and not receipts_match:
            reason = "receipt_root_mismatch"
        elif fraud_suspected and state_delta_match is False:
            reason = "state_delta_hash_mismatch"
        else:
            reason = decision.reason
        results.append(
            LaneAuditResult(
                lane_id=decision.lane_id,
                helper_id=decision.helper_id,
                checked=True,
                receipts_match=bool(receipts_match),
                state_delta_match=state_delta_match,
                expected_receipts_root=expected_receipts_root,
                helper_receipts_root=helper_receipts_root,
                expected_state_delta_hash=expected_state_delta_hash,
                helper_state_delta_hash=helper_state_delta_hash,
                fraud_suspected=bool(fraud_suspected),
                reason=reason,
                tx_ids=decision.tx_ids,
                plan_id=lane_plan_id,
            )
        )
    results.sort(key=lambda item: item.lane_id)
    return tuple(results)


def summarize_lane_audit_results(
    *,
    audit_plan: Sequence[LaneAuditDecision],
    audit_results: Sequence[LaneAuditResult],
) -> Json:
    plan_rows = [item.to_json() for item in list(audit_plan or [])]
    result_rows = [item.to_json() for item in list(audit_results or [])]
    fraud_lanes = [item.lane_id for item in list(audit_results or []) if item.fraud_suspected]
    plan_ids = sorted({str(item.plan_id or "") for item in list(audit_results or []) if str(item.plan_id or "")})
    return {
        "planned": len(plan_rows),
        "selected": sum(1 for item in list(audit_plan or []) if item.selected),
        "checked": len(result_rows),
        "fraud_suspected": bool(fraud_lanes),
        "fraud_lane_ids": fraud_lanes,
        "plan_ids": plan_ids,
        "plan": plan_rows,
        "results": result_rows,
    }


__all__ = [
    "LaneAuditDecision",
    "LaneAuditResult",
    "build_lane_audit_plan",
    "evaluate_lane_audit_plan",
    "summarize_lane_audit_results",
]
