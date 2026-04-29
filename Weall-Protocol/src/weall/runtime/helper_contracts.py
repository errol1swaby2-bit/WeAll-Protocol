from __future__ import annotations

from dataclasses import asdict, dataclass
import json
from pathlib import Path
from typing import Any, Mapping

from weall.runtime.execution_lanes import ALL_LANES, LANE_SERIAL
from weall.runtime.helper_instance_corpus import DEFAULT_HELPER_INSTANCE_CORPUS
from weall.runtime.lane_assignment import assign_execution_lane
from weall.runtime.read_write_sets import TxAccessSet, build_tx_access_set
from weall.runtime.tx_conflicts import BarrierClass, TxFamily, build_conflict_descriptor

Json = dict[str, Any]
_DEFAULT_TX_INDEX_PATH = Path(__file__).resolve().parents[3] / "generated" / "tx_index.json"
_PLANNER_PARALLEL_HINTS: frozenset[str] = frozenset({"IDENTITY", "SOCIAL", "CONTENT", "ECONOMICS", "STORAGE"})


@dataclass(frozen=True, slots=True)
class HelperContract:
    tx_type: str
    family: str
    barrier_class: str
    planner_lane_hint: str
    execution_lane_id: str
    effective_lane_id: str
    helper_eligible: bool
    degraded_to_serial: bool
    derived_only: bool
    fail_closed_serial: bool
    serial_only_on_missing_fields: bool
    reason: str
    proof_status: str
    proven_helper_eligible: bool
    requires_concrete_instance: bool
    uses_placeholder_keys: bool
    placeholder_key_count: int
    has_global_barrier_authority: bool
    subject_keys: tuple[str, ...]
    read_keys: tuple[str, ...]
    write_keys: tuple[str, ...]
    authority_keys: tuple[str, ...]

    def to_dict(self) -> Json:
        out = asdict(self)
        for key in ("subject_keys", "read_keys", "write_keys", "authority_keys"):
            out[key] = list(out[key])
        return out


def _canon_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _tx_type_of(tx: Mapping[str, Any]) -> str:
    return str(tx.get("tx_type") or tx.get("type") or "").strip().upper()


def _is_parallel_lane(lane_id: str) -> bool:
    lane_id2 = str(lane_id or "").strip().upper()
    return bool(lane_id2) and lane_id2 in ALL_LANES and lane_id2 != LANE_SERIAL


def _has_parallel_planner_hint(lane_hint: str) -> bool:
    return str(lane_hint or "").strip().upper() in _PLANNER_PARALLEL_HINTS


def _normalize_tx(tx: Mapping[str, Any]) -> Json:
    return json.loads(_canon_json(dict(tx)))


def _all_contract_keys(subject_keys: tuple[str, ...], read_keys: tuple[str, ...], write_keys: tuple[str, ...], authority_keys: tuple[str, ...]) -> tuple[str, ...]:
    return tuple(subject_keys) + tuple(read_keys) + tuple(write_keys) + tuple(authority_keys)


def _is_placeholder_key(key: str) -> bool:
    return ":anon:" in str(key or "")


def _proof_status(*, helper_eligible: bool, degraded_to_serial: bool, uses_placeholder_keys: bool, has_global_barrier_authority: bool) -> tuple[str, bool, bool]:
    if helper_eligible and not uses_placeholder_keys and not has_global_barrier_authority:
        return ("PROVEN_PARALLEL_SAFE", True, False)
    if helper_eligible and has_global_barrier_authority:
        return ("GLOBAL_AUTHORITY_RISK", False, False)
    if helper_eligible and uses_placeholder_keys:
        return ("INSTANCE_REQUIRED", False, True)
    if degraded_to_serial and uses_placeholder_keys:
        return ("DEGRADED_INSTANCE_REQUIRED", False, True)
    if degraded_to_serial:
        return ("DEGRADED_TO_SERIAL", False, False)
    return ("SERIAL_ONLY", False, False)


def helper_contract_for_tx(tx: Mapping[str, Any]) -> HelperContract:
    txj = _normalize_tx(tx)
    tx_type = _tx_type_of(txj)
    descriptor = build_conflict_descriptor(txj)
    access: TxAccessSet = build_tx_access_set(txj)
    execution_lane_id = str(assign_execution_lane(txj, None) or LANE_SERIAL)

    degraded_to_serial = False
    helper_eligible = False
    effective_lane_id = LANE_SERIAL
    reason = "serial_by_default"

    if descriptor.family == TxFamily.UNKNOWN:
        reason = "unknown_tx_family"
    elif access.fail_closed_serial:
        reason = "fail_closed_serial"
    elif descriptor.barrier_class == BarrierClass.GLOBAL_BARRIER:
        reason = "global_barrier"
    elif any(str(key).startswith("barrier:global") for key in descriptor.authority_keys):
        reason = "global_authority_placeholder"
    elif not _has_parallel_planner_hint(access.lane_hint):
        reason = "planner_serial"
    elif not _is_parallel_lane(execution_lane_id):
        degraded_to_serial = True
        reason = "execution_lane_serial"
    else:
        helper_eligible = True
        effective_lane_id = execution_lane_id
        reason = "helper_parallel_allowed"

    all_keys = _all_contract_keys(
        tuple(descriptor.subject_keys),
        tuple(descriptor.read_keys),
        tuple(descriptor.write_keys),
        tuple(descriptor.authority_keys),
    )
    placeholder_key_count = sum(1 for key in all_keys if _is_placeholder_key(key))
    uses_placeholder_keys = bool(placeholder_key_count)
    has_global_barrier_authority = any(str(key).startswith("barrier:global") for key in descriptor.authority_keys)
    proof_status, proven_helper_eligible, requires_concrete_instance = _proof_status(
        helper_eligible=helper_eligible,
        degraded_to_serial=degraded_to_serial,
        uses_placeholder_keys=uses_placeholder_keys,
        has_global_barrier_authority=has_global_barrier_authority,
    )

    return HelperContract(
        tx_type=tx_type,
        family=descriptor.family.value,
        barrier_class=descriptor.barrier_class.value,
        planner_lane_hint=str(access.lane_hint),
        execution_lane_id=execution_lane_id,
        effective_lane_id=effective_lane_id,
        helper_eligible=helper_eligible,
        degraded_to_serial=degraded_to_serial,
        derived_only=bool(descriptor.derived_only),
        fail_closed_serial=bool(access.fail_closed_serial),
        serial_only_on_missing_fields=bool(descriptor.serial_only_on_missing_fields),
        reason=reason,
        proof_status=proof_status,
        proven_helper_eligible=proven_helper_eligible,
        requires_concrete_instance=requires_concrete_instance,
        uses_placeholder_keys=uses_placeholder_keys,
        placeholder_key_count=int(placeholder_key_count),
        has_global_barrier_authority=has_global_barrier_authority,
        subject_keys=tuple(descriptor.subject_keys),
        read_keys=tuple(descriptor.read_keys),
        write_keys=tuple(descriptor.write_keys),
        authority_keys=tuple(descriptor.authority_keys),
    )


def _load_tx_types(tx_index_path: Path | str = _DEFAULT_TX_INDEX_PATH) -> list[Json]:
    path = Path(tx_index_path)
    data = json.loads(path.read_text(encoding="utf-8"))
    tx_types = data.get("tx_types")
    if not isinstance(tx_types, list):
        raise ValueError(f"tx_index missing tx_types list: {path}")
    cleaned: list[Json] = []
    for row in tx_types:
        if not isinstance(row, dict):
            continue
        name = str(row.get("name") or "").strip().upper()
        if not name:
            continue
        item = dict(row)
        item["name"] = name
        cleaned.append(item)
    return cleaned



def build_helper_instance_contract_map(corpus: list[Mapping[str, Any]] | None = None) -> Json:
    rows = list(DEFAULT_HELPER_INSTANCE_CORPUS if corpus is None else corpus)
    contracts: list[Json] = []
    proof_status_counts: dict[str, int] = {}
    effective_lane_counts: dict[str, int] = {}
    family_counts: dict[str, int] = {}
    degraded_to_serial: list[str] = []

    for idx, row in enumerate(rows):
        tx = _normalize_tx(dict(row))
        tx_type = _tx_type_of(tx)
        contract = helper_contract_for_tx(tx)
        proof_status_counts[contract.proof_status] = int(proof_status_counts.get(contract.proof_status, 0)) + 1
        effective_lane_counts[contract.effective_lane_id] = int(effective_lane_counts.get(contract.effective_lane_id, 0)) + 1
        family_counts[contract.family] = int(family_counts.get(contract.family, 0)) + 1
        if contract.degraded_to_serial:
            degraded_to_serial.append(f"{idx}:{tx_type}")
        contracts.append({
            "sample_index": idx,
            **tx,
            **contract.to_dict(),
        })

    return {
        "summary": {
            "sample_count": len(contracts),
            "proven_helper_eligible_count": sum(1 for item in contracts if bool(item["proven_helper_eligible"])),
            "helper_eligible_count": sum(1 for item in contracts if bool(item["helper_eligible"])),
            "degraded_to_serial_count": sum(1 for item in contracts if bool(item["degraded_to_serial"])),
            "instance_required_count": sum(1 for item in contracts if bool(item["requires_concrete_instance"])),
            "placeholder_parallel_count": sum(1 for item in contracts if bool(item["helper_eligible"]) and bool(item["uses_placeholder_keys"])),
            "proof_status_counts": dict(sorted(proof_status_counts.items())),
            "effective_lane_counts": dict(sorted(effective_lane_counts.items())),
            "family_counts": dict(sorted(family_counts.items())),
        },
        "degraded_to_serial": degraded_to_serial,
        "contracts": contracts,
    }

def build_helper_contract_map(tx_index_path: Path | str = _DEFAULT_TX_INDEX_PATH) -> Json:
    rows = _load_tx_types(tx_index_path)
    contracts: list[Json] = []
    duplicate_names: list[str] = []
    seen: set[str] = set()
    family_counts: dict[str, int] = {}
    effective_lane_counts: dict[str, int] = {}
    reason_counts: dict[str, int] = {}
    degraded_to_serial: list[str] = []

    for row in rows:
        tx_type = str(row["name"])
        if tx_type in seen:
            duplicate_names.append(tx_type)
            continue
        seen.add(tx_type)
        base_tx = {"tx_type": tx_type, "type": tx_type}
        contract = helper_contract_for_tx(base_tx)
        family_counts[contract.family] = int(family_counts.get(contract.family, 0)) + 1
        effective_lane_counts[contract.effective_lane_id] = int(effective_lane_counts.get(contract.effective_lane_id, 0)) + 1
        reason_counts[contract.reason] = int(reason_counts.get(contract.reason, 0)) + 1
        if contract.degraded_to_serial:
            degraded_to_serial.append(tx_type)
        contracts.append(
            {
                "tx_type": tx_type,
                "domain": row.get("domain"),
                "origin": row.get("origin"),
                "context": row.get("context"),
                "receipt_only": bool(row.get("receipt_only", False)),
                **contract.to_dict(),
            }
        )

    contracts.sort(key=lambda item: str(item["tx_type"]))
    degraded_to_serial.sort()
    instance_map = build_helper_instance_contract_map()

    return {
        "summary": {
            "tx_count": len(contracts),
            "duplicate_name_count": len(duplicate_names),
            "unknown_family_count": sum(1 for item in contracts if item["family"] == TxFamily.UNKNOWN.value),
            "helper_eligible_count": sum(1 for item in contracts if bool(item["helper_eligible"])),
            "proven_helper_eligible_count": sum(1 for item in contracts if bool(item["proven_helper_eligible"])),
            "instance_required_count": sum(1 for item in contracts if bool(item["requires_concrete_instance"])),
            "placeholder_parallel_count": sum(1 for item in contracts if bool(item["helper_eligible"]) and bool(item["uses_placeholder_keys"])),
            "global_authority_parallel_count": sum(1 for item in contracts if bool(item["helper_eligible"]) and bool(item["has_global_barrier_authority"])),
            "degraded_to_serial_count": len(degraded_to_serial),
            "family_counts": dict(sorted(family_counts.items())),
            "effective_lane_counts": dict(sorted(effective_lane_counts.items())),
            "reason_counts": dict(sorted(reason_counts.items())),
        },
        "instance_summary": instance_map["summary"],
        "degraded_to_serial": degraded_to_serial,
        "duplicates": sorted(duplicate_names),
        "contracts": contracts,
        "instance_contracts": instance_map["contracts"],
    }


def summarize_helper_contracts(tx_index_path: Path | str = _DEFAULT_TX_INDEX_PATH) -> Json:
    return build_helper_contract_map(tx_index_path)["summary"]


def summarize_helper_instance_contracts(corpus: list[Mapping[str, Any]] | None = None) -> Json:
    return build_helper_instance_contract_map(corpus)["summary"]


__all__ = [
    "HelperContract",
    "build_helper_contract_map",
    "helper_contract_for_tx",
    "build_helper_instance_contract_map",
    "summarize_helper_contracts",
    "summarize_helper_instance_contracts",
]

