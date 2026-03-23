from __future__ import annotations

from typing import Any, Iterable, Mapping, Sequence

Json = dict[str, Any]


def _clean_strs(values: Iterable[Any] | None) -> tuple[str, ...]:
    cleaned: list[str] = []
    for value in list(values or []):
        text = str(value or "").strip()
        if text:
            cleaned.append(text)
    return tuple(sorted(dict.fromkeys(cleaned)))


def lane_class_for_plan(*, lane_id: str, tx_types: Sequence[str] | None = None) -> str:
    lane = str(lane_id or "").strip().upper()
    if "#" in lane:
        lane = lane.split("#", 1)[0]
    if lane in {"CONTENT", "IDENTITY", "SOCIAL", "ECONOMICS", "STORAGE", "GOVERNANCE", "SERIAL"}:
        return lane.lower()

    observed = [str(v or "").strip().upper() for v in list(tx_types or []) if str(v or "").strip()]
    for tx_type in observed:
        if tx_type.startswith(("CONTENT_", "INDEXING_")):
            return "content"
        if tx_type.startswith(("IDENTITY_", "POH_")):
            return "identity"
        if tx_type.startswith(("SOCIAL_", "REPUTATION_", "NOTIFICATION_", "MESSAGING_")):
            return "social"
        if tx_type.startswith(("ECONOMICS_", "TREASURY_", "REWARDS_")):
            return "economics"
        if tx_type.startswith("STORAGE_"):
            return "storage"
        if tx_type.startswith(("GOV_", "GROUP_", "ROLE_")):
            return "governance"
    return lane.lower() if lane else "serial"


def normalize_helper_capability_map(raw: Mapping[str, Any] | None) -> dict[str, Json]:
    normalized: dict[str, Json] = {}
    if not isinstance(raw, Mapping):
        return normalized
    for helper_id, value in dict(raw).items():
        hid = str(helper_id or "").strip()
        if not hid:
            continue
        if isinstance(value, Mapping):
            payload = dict(value)
            allow_all = bool(payload.get("allow_all") or payload.get("all") or payload.get("wildcard"))
            lane_classes = _clean_strs(payload.get("lane_classes") or payload.get("lanes"))
            tx_types = tuple(v.upper() for v in _clean_strs(payload.get("tx_types")))
            normalized[hid] = {
                "allow_all": allow_all or "*" in lane_classes,
                "lane_classes": tuple(v.lower() for v in lane_classes if v != "*"),
                "tx_types": tx_types,
                "max_complexity": int(payload.get("max_complexity") or 0),
            }
            continue
        if isinstance(value, (list, tuple, set)):
            lane_classes = _clean_strs(value)
            normalized[hid] = {
                "allow_all": "*" in lane_classes,
                "lane_classes": tuple(v.lower() for v in lane_classes if v != "*"),
                "tx_types": (),
                "max_complexity": 0,
            }
            continue
        text = str(value or "").strip()
        if not text:
            continue
        normalized[hid] = {
            "allow_all": text == "*",
            "lane_classes": () if text == "*" else (text.lower(),),
            "tx_types": (),
            "max_complexity": 0,
        }
    return normalized


def helper_supports_lane(
    helper_id: str,
    *,
    helper_capability_by_helper: Mapping[str, Any] | None,
    lane_class: str,
    tx_types: Sequence[str] | None = None,
    lane_cost_units: int = 1,
) -> bool:
    normalized = normalize_helper_capability_map(helper_capability_by_helper)
    capability = normalized.get(str(helper_id or "").strip())
    if capability is None:
        return True
    if bool(capability.get("allow_all")):
        max_complexity = int(capability.get("max_complexity") or 0)
        return max_complexity <= 0 or int(lane_cost_units) <= max_complexity

    lane_classes = {str(v).lower() for v in list(capability.get("lane_classes") or ()) if str(v).strip()}
    tx_type_caps = {str(v).upper() for v in list(capability.get("tx_types") or ()) if str(v).strip()}
    lane_class_ok = not lane_classes or str(lane_class or "").lower() in lane_classes
    tx_type_list = [str(v or "").strip().upper() for v in list(tx_types or []) if str(v or "").strip()]
    tx_types_ok = not tx_type_caps or all(tx in tx_type_caps for tx in tx_type_list)
    max_complexity = int(capability.get("max_complexity") or 0)
    complexity_ok = max_complexity <= 0 or int(lane_cost_units) <= max_complexity
    return lane_class_ok and tx_types_ok and complexity_ok


def filter_helper_candidates_by_capability(
    candidates: Sequence[str] | None,
    *,
    helper_capability_by_helper: Mapping[str, Any] | None,
    lane_class: str,
    tx_types: Sequence[str] | None = None,
    lane_cost_units: int = 1,
) -> tuple[str, ...]:
    ordered = tuple(str(v) for v in list(candidates or []) if str(v))
    if not ordered:
        return ()
    allowed = [
        helper_id
        for helper_id in ordered
        if helper_supports_lane(
            helper_id,
            helper_capability_by_helper=helper_capability_by_helper,
            lane_class=lane_class,
            tx_types=tx_types,
            lane_cost_units=lane_cost_units,
        )
    ]
    return tuple(allowed)


def summarize_helper_capabilities(helper_capability_by_helper: Mapping[str, Any] | None) -> Json:
    normalized = normalize_helper_capability_map(helper_capability_by_helper)
    rows: list[Json] = []
    for helper_id, payload in sorted(normalized.items()):
        rows.append(
            {
                "helper_id": helper_id,
                "allow_all": bool(payload.get("allow_all")),
                "lane_classes": list(payload.get("lane_classes") or ()),
                "tx_types": list(payload.get("tx_types") or ()),
                "max_complexity": int(payload.get("max_complexity") or 0),
            }
        )
    return {
        "helper_count": len(rows),
        "restricted_helper_count": sum(1 for row in rows if (not row["allow_all"]) or row["max_complexity"] > 0),
        "helpers": rows,
    }


__all__ = [
    "filter_helper_candidates_by_capability",
    "helper_supports_lane",
    "lane_class_for_plan",
    "normalize_helper_capability_map",
    "summarize_helper_capabilities",
]
