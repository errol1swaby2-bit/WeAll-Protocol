from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
import json
from typing import Any, Dict, Iterable, List, Mapping, Sequence, Tuple

from .conflict_lanes import lane_base_id as planned_lane_base_id
from .read_write_sets import build_tx_access_set
from .tx_conflicts import build_conflict_descriptor


def _canon_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _sha256_hex(value: Any) -> str:
    if not isinstance(value, str):
        value = _canon_json(value)
    return sha256(value.encode("utf-8")).hexdigest()


def normalize_validators(validators: Iterable[str]) -> List[str]:
    seen = set()
    ordered: List[str] = []
    for validator in sorted(str(v) for v in validators):
        if validator not in seen:
            ordered.append(validator)
            seen.add(validator)
    return ordered


def stable_tx_id(tx: Mapping[str, Any]) -> str:
    tx_id = tx.get("tx_id")
    if isinstance(tx_id, str) and tx_id:
        return tx_id
    return _sha256_hex(tx)


def canonical_tx_order_key(tx: Mapping[str, Any]) -> Tuple[int, str]:
    received_ms = int(tx.get("received_ms", 0) or 0)
    return (received_ms, stable_tx_id(tx))


def canonicalize_txs(txs: Sequence[Mapping[str, Any]]) -> List[Dict[str, Any]]:
    return sorted((dict(tx) for tx in txs), key=canonical_tx_order_key)


def tx_conflict_keys(tx: Mapping[str, Any]) -> List[str]:
    descriptor = build_conflict_descriptor(tx)
    keys = list(descriptor.subject_keys) + list(descriptor.read_keys) + list(descriptor.write_keys) + list(descriptor.authority_keys)
    if keys:
        return sorted(set(keys))
    raw = tx.get("conflict_keys")
    if isinstance(raw, list) and raw:
        return sorted({str(x) for x in raw})
    signer = str(tx.get("signer", ""))
    tx_type = str(tx.get("tx_type", ""))
    if signer:
        return [f"signer:{signer}", f"type:{tx_type}"]
    tx_id = stable_tx_id(tx)
    return [f"tx:{tx_id}", f"type:{tx_type}"]


def lane_base_id(tx: Mapping[str, Any]) -> str:
    access = build_tx_access_set(dict(tx))
    base = planned_lane_base_id(access.lane_hint)
    if access.fail_closed_serial or base == "SERIAL":
        tx_id = stable_tx_id(tx)
        return f"SERIAL:{tx_id}"
    if access.barrier_class == "GLOBAL_BARRIER":
        tx_id = stable_tx_id(tx)
        return f"SERIAL:{tx_id}"
    conflict_material = {
        "base": base,
        "subject_keys": list(access.subject_keys),
        "authority_keys": list(access.authority_keys),
        "writes": list(access.writes),
    }
    return f"{base}:{_sha256_hex(conflict_material)}"


@dataclass(frozen=True)
class LaneAssignment:
    lane_id: str
    helper_id: str
    tx_ids: Tuple[str, ...]


@dataclass(frozen=True)
class HelperPlan:
    chain_id: str
    height: int
    parent_block_id: str
    validator_epoch: int
    validator_set_hash: str
    lanes: Tuple[LaneAssignment, ...]

    def to_canonical_dict(self) -> Dict[str, Any]:
        return {
            "chain_id": self.chain_id,
            "height": self.height,
            "parent_block_id": self.parent_block_id,
            "validator_epoch": self.validator_epoch,
            "validator_set_hash": self.validator_set_hash,
            "lanes": [
                {
                    "lane_id": lane.lane_id,
                    "helper_id": lane.helper_id,
                    "tx_ids": list(lane.tx_ids),
                }
                for lane in self.lanes
            ],
        }

    def plan_hash(self) -> str:
        return _sha256_hex(self.to_canonical_dict())


def validator_set_hash(validators: Sequence[str]) -> str:
    normalized = normalize_validators(validators)
    return _sha256_hex(normalized)


def choose_helper_for_lane(
    validators: Sequence[str],
    chain_id: str,
    height: int,
    parent_block_id: str,
    validator_epoch: int,
    lane_id: str,
) -> str:
    normalized = normalize_validators(validators)
    if not normalized:
        raise ValueError("cannot choose helper from empty validator set")

    selector = _sha256_hex(
        {
            "chain_id": chain_id,
            "height": int(height),
            "parent_block_id": str(parent_block_id),
            "validator_epoch": int(validator_epoch),
            "lane_id": str(lane_id),
            "validator_set": normalized,
        }
    )
    idx = int(selector[:16], 16) % len(normalized)
    return normalized[idx]


def partition_conflict_lanes(
    txs: Sequence[Mapping[str, Any]],
) -> List[Tuple[str, List[Dict[str, Any]]]]:
    ordered = canonicalize_txs(txs)
    lanes: Dict[str, List[Dict[str, Any]]] = {}
    order: List[str] = []
    for tx in ordered:
        lane_id = lane_base_id(tx)
        if lane_id not in lanes:
            lanes[lane_id] = []
            order.append(lane_id)
        lanes[lane_id].append(tx)
    return [(lane_id, lanes[lane_id]) for lane_id in order]


def build_helper_plan(
    *,
    chain_id: str,
    height: int,
    parent_block_id: str,
    validator_epoch: int,
    validators: Sequence[str],
    txs: Sequence[Mapping[str, Any]],
) -> HelperPlan:
    normalized = normalize_validators(validators)
    if not normalized:
        raise ValueError("helper planning requires a non-empty validator set")

    vset_hash = validator_set_hash(normalized)
    lane_tuples = partition_conflict_lanes(txs)

    assignments: List[LaneAssignment] = []
    for lane_id, lane_txs in lane_tuples:
        helper_id = choose_helper_for_lane(
            validators=normalized,
            chain_id=chain_id,
            height=height,
            parent_block_id=parent_block_id,
            validator_epoch=validator_epoch,
            lane_id=lane_id,
        )
        tx_ids = tuple(stable_tx_id(tx) for tx in lane_txs)
        assignments.append(
            LaneAssignment(
                lane_id=lane_id,
                helper_id=helper_id,
                tx_ids=tx_ids,
            )
        )

    return HelperPlan(
        chain_id=str(chain_id),
        height=int(height),
        parent_block_id=str(parent_block_id),
        validator_epoch=int(validator_epoch),
        validator_set_hash=vset_hash,
        lanes=tuple(assignments),
    )
