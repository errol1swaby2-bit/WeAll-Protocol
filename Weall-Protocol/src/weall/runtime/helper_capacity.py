from __future__ import annotations

from typing import Any, Mapping, Sequence

Json = dict[str, object]

DEFAULT_HELPER_CAPACITY_UNITS = 8
DEFAULT_SERIAL_CAPACITY_UNITS = 0


def _safe_int(value: Any, default: int) -> int:
    try:
        return int(value)
    except Exception:
        return int(default)


def normalize_helper_capacity_map(
    helper_capacity_by_helper: Mapping[str, Any] | None,
    *,
    default_capacity_units: int = DEFAULT_HELPER_CAPACITY_UNITS,
) -> dict[str, int]:
    normalized: dict[str, int] = {}
    for helper_id, raw in dict(helper_capacity_by_helper or {}).items():
        hid = str(helper_id or '').strip()
        if not hid:
            continue
        normalized[hid] = max(0, _safe_int(raw, default_capacity_units))
    return normalized


def lane_cost_units(
    *,
    lane_id: str,
    tx_count: int,
    namespace_prefixes: Sequence[str] | None = None,
    override_units: int | None = None,
) -> int:
    if override_units is not None:
        return max(1, int(override_units))
    lid = str(lane_id or '').strip().upper()
    if lid == 'SERIAL':
        return 1
    prefixes = tuple(str(v).strip().lower() for v in list(namespace_prefixes or []) if str(v).strip())
    units = 1
    if tx_count >= 8:
        units += 2
    elif tx_count >= 4:
        units += 1
    if any(prefix.startswith((
        'economics:', 'treasury:', 'governance:', 'identity:', 'poh:', 'roles:', 'group:'
    )) for prefix in prefixes):
        units += 1
    return max(1, int(units))


def summarize_helper_capacity_usage(
    *,
    helper_capacity_by_helper: Mapping[str, Any] | None,
    helper_load_by_helper: Mapping[str, Any] | None,
) -> Json:
    capacities = normalize_helper_capacity_map(helper_capacity_by_helper)
    loads = {str(k): _safe_int(v, 0) for k, v in dict(helper_load_by_helper or {}).items() if str(k).strip()}
    helper_ids = sorted(set(capacities) | set(loads))
    rows: list[Json] = []
    saturated: list[str] = []
    for helper_id in helper_ids:
        capacity_units = max(0, capacities.get(helper_id, DEFAULT_HELPER_CAPACITY_UNITS))
        load_units = max(0, loads.get(helper_id, 0))
        available_units = max(0, capacity_units - load_units)
        saturated_now = capacity_units > 0 and load_units >= capacity_units
        if saturated_now:
            saturated.append(helper_id)
        rows.append({
            'helper_id': helper_id,
            'capacity_units': int(capacity_units),
            'load_units': int(load_units),
            'available_units': int(available_units),
            'saturated': bool(saturated_now),
        })
    return {
        'helper_count': len(rows),
        'saturated_helper_ids': saturated,
        'by_helper': rows,
        'capacity_units_total': sum(int(row['capacity_units']) for row in rows),
        'load_units_total': sum(int(row['load_units']) for row in rows),
    }


__all__ = [
    'DEFAULT_HELPER_CAPACITY_UNITS',
    'DEFAULT_SERIAL_CAPACITY_UNITS',
    'lane_cost_units',
    'normalize_helper_capacity_map',
    'summarize_helper_capacity_usage',
]
