from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping, Sequence

from weall.runtime.helper_audit import LaneAuditResult
from weall.runtime.parallel_execution import LanePlan

Json = dict[str, Any]


def _safe_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except Exception:
        return int(default)


@dataclass(frozen=True, slots=True)
class HelperReputationRecord:
    helper_id: str
    audits_total: int = 0
    success_count: int = 0
    fraud_count: int = 0
    timeout_count: int = 0
    quarantine_until_ms: int = 0
    last_event_ms: int = 0
    last_reason: str = ""

    def to_json(self) -> Json:
        score = max(0, (self.success_count * 2) - (self.fraud_count * 10) - (self.timeout_count * 4))
        return {
            "helper_id": self.helper_id,
            "audits_total": int(self.audits_total),
            "success_count": int(self.success_count),
            "fraud_count": int(self.fraud_count),
            "timeout_count": int(self.timeout_count),
            "quarantine_until_ms": int(self.quarantine_until_ms),
            "last_event_ms": int(self.last_event_ms),
            "last_reason": str(self.last_reason),
            "score": int(score),
            "quarantined": int(self.quarantine_until_ms) > int(self.last_event_ms),
        }

    @classmethod
    def from_json(cls, payload: Mapping[str, Any]) -> "HelperReputationRecord":
        return cls(
            helper_id=str(payload.get("helper_id") or ""),
            audits_total=_safe_int(payload.get("audits_total"), 0),
            success_count=_safe_int(payload.get("success_count"), 0),
            fraud_count=_safe_int(payload.get("fraud_count"), 0),
            timeout_count=_safe_int(payload.get("timeout_count"), 0),
            quarantine_until_ms=_safe_int(payload.get("quarantine_until_ms"), 0),
            last_event_ms=_safe_int(payload.get("last_event_ms"), 0),
            last_reason=str(payload.get("last_reason") or ""),
        )


DEFAULT_QUARANTINE_FRAUD_MS = 30 * 60 * 1000
DEFAULT_QUARANTINE_TIMEOUT_MS = 10 * 60 * 1000


def _normalized_state(helper_reputation_state: Mapping[str, Any] | None) -> dict[str, HelperReputationRecord]:
    normalized: dict[str, HelperReputationRecord] = {}
    for helper_id, raw in dict(helper_reputation_state or {}).items():
        hid = str(helper_id or "").strip()
        if not hid:
            continue
        if isinstance(raw, HelperReputationRecord):
            normalized[hid] = raw
        elif isinstance(raw, Mapping):
            payload = dict(raw)
            payload.setdefault("helper_id", hid)
            normalized[hid] = HelperReputationRecord.from_json(payload)
        else:
            normalized[hid] = HelperReputationRecord(helper_id=hid)
    return normalized


def update_helper_reputation_state(
    *,
    helper_reputation_state: Mapping[str, Any] | None,
    audit_results: Sequence[LaneAuditResult] | Sequence[Mapping[str, Any]] | None,
    timed_out_lane_ids: Sequence[str] | None,
    lane_plans: Sequence[LanePlan] | None,
    now_ms: int,
    fraud_quarantine_ms: int = DEFAULT_QUARANTINE_FRAUD_MS,
    timeout_quarantine_ms: int = DEFAULT_QUARANTINE_TIMEOUT_MS,
) -> Json:
    records = _normalized_state(helper_reputation_state)
    lane_to_helper: dict[str, str] = {}
    for lane in list(lane_plans or []):
        if getattr(lane, "helper_id", None):
            lane_to_helper[str(lane.lane_id)] = str(lane.helper_id)

    for raw in list(audit_results or []):
        result = raw if isinstance(raw, LaneAuditResult) else LaneAuditResult(**dict(raw))
        helper_id = str(result.helper_id or lane_to_helper.get(str(result.lane_id)) or "").strip()
        if not helper_id:
            continue
        current = records.get(helper_id, HelperReputationRecord(helper_id=helper_id))
        fraud = bool(result.fraud_suspected)
        records[helper_id] = HelperReputationRecord(
            helper_id=helper_id,
            audits_total=int(current.audits_total) + 1,
            success_count=int(current.success_count) + (0 if fraud else 1),
            fraud_count=int(current.fraud_count) + (1 if fraud else 0),
            timeout_count=int(current.timeout_count),
            quarantine_until_ms=max(
                int(current.quarantine_until_ms),
                int(now_ms) + (int(fraud_quarantine_ms) if fraud else 0),
            ),
            last_event_ms=int(now_ms),
            last_reason=str(result.reason or ("audit_ok" if not fraud else "audit_fraud")),
        )

    for lane_id in list(timed_out_lane_ids or []):
        helper_id = str(lane_to_helper.get(str(lane_id)) or "").strip()
        if not helper_id:
            continue
        current = records.get(helper_id, HelperReputationRecord(helper_id=helper_id))
        records[helper_id] = HelperReputationRecord(
            helper_id=helper_id,
            audits_total=int(current.audits_total),
            success_count=int(current.success_count),
            fraud_count=int(current.fraud_count),
            timeout_count=int(current.timeout_count) + 1,
            quarantine_until_ms=max(int(current.quarantine_until_ms), int(now_ms) + int(timeout_quarantine_ms)),
            last_event_ms=int(now_ms),
            last_reason="helper_timeout",
        )

    return {helper_id: record.to_json() for helper_id, record in sorted(records.items())}


def apply_helper_quarantine_to_lane_plans(
    lane_plans: Sequence[LanePlan],
    *,
    helper_reputation_state: Mapping[str, Any] | None,
    now_ms: int,
) -> tuple[LanePlan, ...]:
    records = _normalized_state(helper_reputation_state)
    updated: list[LanePlan] = []
    for lane in list(lane_plans or []):
        helper_id = str(getattr(lane, "helper_id", "") or "").strip()
        if not helper_id:
            updated.append(lane)
            continue
        record = records.get(helper_id)
        quarantine_until_ms = int(record.quarantine_until_ms) if record else 0
        if quarantine_until_ms > int(now_ms):
            updated.append(
                LanePlan(
                    lane_id=str(lane.lane_id),
                    helper_id=None,
                    txs=tuple(lane.txs),
                    tx_ids=tuple(lane.tx_ids),
                    access_sets=tuple(lane.access_sets),
                    namespace_prefixes=tuple(lane.namespace_prefixes),
                )
            )
            continue
        updated.append(lane)
    return tuple(updated)


def summarize_helper_reputation_state(
    *,
    helper_reputation_state: Mapping[str, Any] | None,
    now_ms: int,
) -> Json:
    records = _normalized_state(helper_reputation_state)
    rows: list[Json] = []
    quarantined_helpers: list[str] = []
    for helper_id, record in sorted(records.items()):
        row = record.to_json()
        row["quarantined"] = int(record.quarantine_until_ms) > int(now_ms)
        rows.append(row)
        if row["quarantined"]:
            quarantined_helpers.append(helper_id)
    return {
        "quarantined": bool(quarantined_helpers),
        "quarantined_helper_ids": quarantined_helpers,
        "record_count": len(rows),
        "state": {row["helper_id"]: dict(row) for row in rows},
        "records": rows,
        "quarantined_lane_overrides": [],
    }


__all__ = [
    "HelperReputationRecord",
    "apply_helper_quarantine_to_lane_plans",
    "summarize_helper_reputation_state",
    "update_helper_reputation_state",
]
