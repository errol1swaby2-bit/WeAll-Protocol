from __future__ import annotations

import hashlib
from typing import Any, Iterable, List, Mapping, Optional, Sequence

from weall.runtime.helper_capacity import (
    DEFAULT_HELPER_CAPACITY_UNITS,
    lane_cost_units as compute_lane_cost_units,
    normalize_helper_capacity_map,
)

Json = dict[str, object]


def normalize_validators(validators: List[str]) -> List[str]:
    return sorted(set(validators))


def _clean_quarantined_helpers(quarantined_helpers: Iterable[str] | None) -> set[str]:
    return {str(v).strip() for v in list(quarantined_helpers or []) if str(v).strip()}


def assign_helper_candidates_for_lane(
    validators_normalized: Sequence[str] | None = None,
    view: int | None = None,
    lane_id: str | None = None,
    leader_id: str | None = None,
    *,
    validators: Sequence[str] | None = None,
    validator_set_hash: str | None = None,
    quarantined_helpers: Iterable[str] | None = None,
) -> tuple[str, ...]:
    """
    Deterministically rank helper candidates for a lane.

    Ordering stays stable for a given validator set / view / lane / leader tuple.
    Quarantined helpers are excluded when healthy candidates exist, but are kept as a
    deterministic fallback tail so the planner can still surface the full candidate set.
    """
    validator_set_hash = str(validator_set_hash or "")

    if validators_normalized is None and validators is not None:
        validators_normalized = normalize_validators(list(validators))
    normalized = [str(v) for v in list(validators_normalized or []) if str(v)]
    if view is None or lane_id is None or leader_id is None or len(normalized) < 2:
        return ()

    eligible = [v for v in normalized if v != str(leader_id)]
    if not eligible:
        return ()

    seed_input = f"{validator_set_hash}:{int(view)}:{str(lane_id)}:{str(leader_id)}".encode()
    seed_hash = hashlib.sha256(seed_input).hexdigest()
    rotation = int(seed_hash, 16) % len(eligible)
    ordered = tuple(eligible[rotation:] + eligible[:rotation])

    quarantined = _clean_quarantined_helpers(quarantined_helpers)
    if not quarantined:
        return ordered

    healthy = tuple(v for v in ordered if v not in quarantined)
    quarantined_tail = tuple(v for v in ordered if v in quarantined)
    return healthy + quarantined_tail


def choose_helper_from_candidates(
    candidates: Sequence[str] | None,
    *,
    assignment_counts: Mapping[str, int] | None = None,
    assignment_load_units: Mapping[str, int] | None = None,
    helper_capacity_by_helper: Mapping[str, Any] | None = None,
    lane_cost: int = 1,
    quarantined_helpers: Iterable[str] | None = None,
    allow_overcommit: bool = True,
) -> Optional[str]:
    """
    Deterministically choose the least-loaded healthy helper from an ordered candidate list.
    Falls back to quarantined candidates only if every candidate is quarantined.
    """
    ordered = tuple(str(v) for v in list(candidates or []) if str(v))
    if not ordered:
        return None

    quarantined = _clean_quarantined_helpers(quarantined_helpers)
    healthy = tuple(v for v in ordered if v not in quarantined)
    pool = healthy if healthy else ordered
    counts = {str(k): int(v) for k, v in dict(assignment_counts or {}).items()}
    loads = {str(k): int(v) for k, v in dict(assignment_load_units or {}).items()}
    capacities = normalize_helper_capacity_map(helper_capacity_by_helper)
    lane_cost = max(1, int(lane_cost))

    under_capacity = [
        helper_id
        for helper_id in pool
        if (loads.get(helper_id, 0) + lane_cost) <= max(0, capacities.get(helper_id, DEFAULT_HELPER_CAPACITY_UNITS))
    ]
    candidate_pool = tuple(under_capacity) if under_capacity else (() if not allow_overcommit else pool)
    if not candidate_pool:
        return None

    def _score(helper_id: str) -> tuple[float, int, int]:
        capacity_units = max(1, capacities.get(helper_id, DEFAULT_HELPER_CAPACITY_UNITS))
        projected_load = loads.get(helper_id, 0) + lane_cost
        overload = max(0, projected_load - capacity_units)
        ratio = projected_load / float(capacity_units)
        return (float(ratio + overload), counts.get(helper_id, 0), candidate_pool.index(helper_id))

    best = min(candidate_pool, key=_score)
    return str(best)


def summarize_assignment_counts(
    *,
    candidates_by_lane: Mapping[str, Sequence[str]] | None,
    assignment_counts: Mapping[str, int] | None,
    chosen_by_lane: Mapping[str, str] | None,
    quarantined_helpers: Iterable[str] | None = None,
    assignment_load_units: Mapping[str, int] | None = None,
    helper_capacity_by_helper: Mapping[str, Any] | None = None,
    lane_cost_by_lane: Mapping[str, int] | None = None,
) -> Json:
    quarantined = _clean_quarantined_helpers(quarantined_helpers)
    counts = {str(k): int(v) for k, v in dict(assignment_counts or {}).items()}
    loads = {str(k): int(v) for k, v in dict(assignment_load_units or {}).items()}
    capacities = normalize_helper_capacity_map(helper_capacity_by_helper)
    lane_costs = {str(k): int(v) for k, v in dict(lane_cost_by_lane or {}).items()}
    rows: list[Json] = []
    for lane_id, candidates in sorted(dict(candidates_by_lane or {}).items()):
        ordered = [str(v) for v in list(candidates or []) if str(v)]
        chosen = str(dict(chosen_by_lane or {}).get(str(lane_id)) or "")
        rows.append(
            {
                "lane_id": str(lane_id),
                "chosen_helper_id": chosen,
                "helper_candidates": ordered,
                "healthy_candidates": [v for v in ordered if v not in quarantined],
                "quarantined_candidates": [v for v in ordered if v in quarantined],
                "lane_cost_units": int(lane_costs.get(str(lane_id), 0)),
            }
        )
    helper_rows = [
        {
            "helper_id": helper_id,
            "assigned_lane_count": int(count),
            "assigned_load_units": int(loads.get(helper_id, 0)),
            "capacity_units": int(capacities.get(helper_id, DEFAULT_HELPER_CAPACITY_UNITS)),
            "quarantined": helper_id in quarantined,
        }
        for helper_id, count in sorted(counts.items())
    ]
    return {
        "lane_count": len(rows),
        "helper_count": len(helper_rows),
        "quarantined_helper_ids": sorted(quarantined),
        "by_lane": rows,
        "by_helper": helper_rows,
    }


def assign_helper_for_lane(
    validators_normalized=None,
    view=None,
    lane_id=None,
    leader_id=None,
    *,
    validators=None,
    validator_set_hash=None,
    quarantined_helpers: Iterable[str] | None = None,
    assignment_counts: Mapping[str, int] | None = None,
    assignment_load_units: Mapping[str, int] | None = None,
    helper_capacity_by_helper: Mapping[str, Any] | None = None,
    lane_cost: int = 1,
    allow_overcommit: bool = True,
) -> Optional[str]:
    """
    Deterministic helper selection.

    Fully backward + forward compatible:
    - positional args (Batch 1 tests)
    - validators_normalized keyword (Batch 2+)
    - validators keyword (legacy convenience)
    - validator_set_hash keyword accepted for forward compatibility

    Optional planning-time controls:
    - quarantined_helpers: avoid known-bad helpers when alternatives exist
    - assignment_counts: deterministic least-loaded helper tie-break
    """
    candidates = assign_helper_candidates_for_lane(
        validators_normalized=validators_normalized,
        view=view,
        lane_id=lane_id,
        leader_id=leader_id,
        validators=validators,
        validator_set_hash=validator_set_hash,
        quarantined_helpers=quarantined_helpers,
    )
    return choose_helper_from_candidates(
        candidates,
        assignment_counts=assignment_counts,
        assignment_load_units=assignment_load_units,
        helper_capacity_by_helper=helper_capacity_by_helper,
        lane_cost=lane_cost,
        quarantined_helpers=quarantined_helpers,
        allow_overcommit=allow_overcommit,
    )


__all__ = [
    "assign_helper_candidates_for_lane",
    "assign_helper_for_lane",
    "choose_helper_from_candidates",
    "normalize_validators",
    "summarize_assignment_counts",
    "compute_lane_cost_units",
]
