from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Iterable, Mapping

from .read_write_sets import TxAccessSet, build_tx_access_set

Json = dict[str, Any]


@dataclass(frozen=True)
class PlannedLane:
    lane_id: str
    tx_ids: tuple[str, ...]
    reads: tuple[str, ...]
    writes: tuple[str, ...]
    base_lane_id: str
    serial_only: bool = False


@dataclass(frozen=True)
class ConflictLanePlan:
    lanes: tuple[PlannedLane, ...]
    serialized_tx_ids: tuple[str, ...]


def lane_base_id(lane_id: str) -> str:
    lane_id = str(lane_id or "SERIAL")
    if "#" in lane_id:
        return lane_id.split("#", 1)[0]
    return lane_id


def _set(values: Iterable[str]) -> set[str]:
    return {str(v) for v in values if str(v).strip()}


def _conflicts(existing: PlannedLane, access: TxAccessSet) -> bool:
    existing_reads = _set(existing.reads)
    existing_writes = _set(existing.writes)
    reads = _set(access.reads)
    writes = _set(access.writes)
    if "barrier:global" in writes or "barrier:global" in existing_writes:
        return True
    if existing_writes & writes:
        return True
    if existing_writes & reads:
        return True
    if existing_reads & writes:
        return True
    return False


def partition_conflict_lanes(access_sets: Iterable[TxAccessSet]) -> tuple[PlannedLane, ...]:
    """
    Deterministic conflict-aware lane partitioning.

    - SERIAL accesses always remain isolated in their own serial lane entries.
    - Global barriers remain isolated.
    - Non-serial accesses are grouped by lane_hint and split only when a true
      read/write or authority conflict exists.
    - Lane numbering is stable in canonical input order.
    """
    grouped: dict[str, list[PlannedLane]] = {}
    group_order: list[str] = []

    for access in access_sets:
        base = lane_base_id(access.lane_hint)
        if access.fail_closed_serial or base == "SERIAL" or access.barrier_class == "GLOBAL_BARRIER":
            if "SERIAL" not in grouped:
                grouped["SERIAL"] = []
                group_order.append("SERIAL")
            serial_group = grouped["SERIAL"]
            lane_id = "SERIAL" if not serial_group else f"SERIAL#{len(serial_group)}"
            serial_group.append(
                PlannedLane(
                    lane_id=lane_id,
                    tx_ids=(access.tx_id,),
                    reads=tuple(access.reads),
                    writes=tuple(access.writes),
                    base_lane_id="SERIAL",
                    serial_only=True,
                )
            )
            continue

        if base not in grouped:
            grouped[base] = []
            group_order.append(base)
        candidates = grouped[base]
        placed = False
        for idx, lane in enumerate(candidates):
            if _conflicts(lane, access):
                continue
            merged_reads = tuple(sorted(set(lane.reads) | set(access.reads)))
            merged_writes = tuple(sorted(set(lane.writes) | set(access.writes)))
            candidates[idx] = PlannedLane(
                lane_id=lane.lane_id,
                tx_ids=lane.tx_ids + (access.tx_id,),
                reads=merged_reads,
                writes=merged_writes,
                base_lane_id=base,
                serial_only=False,
            )
            placed = True
            break
        if placed:
            continue

        lane_index = len(candidates)
        lane_id = base if lane_index == 0 else f"{base}#{lane_index}"
        candidates.append(
            PlannedLane(
                lane_id=lane_id,
                tx_ids=(access.tx_id,),
                reads=tuple(access.reads),
                writes=tuple(access.writes),
                base_lane_id=base,
                serial_only=False,
            )
        )

    ordered: list[PlannedLane] = []
    for base in group_order:
        ordered.extend(grouped[base])
    return tuple(ordered)


def plan_conflict_lanes(txs: Iterable[Mapping[str, Any]]) -> ConflictLanePlan:
    tx_list = [dict(tx) for tx in list(txs or [])]
    access_sets = [build_tx_access_set(tx) for tx in tx_list]
    lanes = partition_conflict_lanes(access_sets)
    serialized_tx_ids = tuple(
        tx_id
        for lane in lanes
        if lane.serial_only or lane_base_id(lane.lane_id) == "SERIAL"
        for tx_id in lane.tx_ids
    )
    return ConflictLanePlan(lanes=lanes, serialized_tx_ids=serialized_tx_ids)


__all__ = [
    "ConflictLanePlan",
    "PlannedLane",
    "lane_base_id",
    "partition_conflict_lanes",
    "plan_conflict_lanes",
]
