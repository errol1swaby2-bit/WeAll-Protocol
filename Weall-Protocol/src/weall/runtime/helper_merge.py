from __future__ import annotations

import copy
from dataclasses import dataclass
from typing import Any

from weall.runtime.execution_lanes import canonical_scope_prefixes
from weall.runtime.helper_certificates import (
    HelperExecutionCertificate,
    hash_json,
    hash_ordered_strings,
    hash_receipts,
    make_namespace_hash,
    validate_certificate_scope,
)
from weall.runtime.parallel_execution import LanePlan

Json = dict[str, Any]


@dataclass(frozen=True, slots=True)
class HelperDeltaOp:
    op: str
    path: str
    value: Any = None

    def to_json(self) -> Json:
        obj: Json = {"op": str(self.op), "path": str(self.path)}
        if self.op == "set":
            obj["value"] = copy.deepcopy(self.value)
        return obj


@dataclass(frozen=True, slots=True)
class MaterializedLaneResult:
    cert: HelperExecutionCertificate
    lane_plan: LanePlan
    namespace_prefixes: tuple[str, ...]
    receipts: tuple[Json, ...]
    read_set: tuple[str, ...]
    write_set: tuple[str, ...]
    delta_ops: tuple[HelperDeltaOp, ...]

    def tx_ids(self) -> tuple[str, ...]:
        return tuple(str(x) for x in self.cert.tx_ids)


@dataclass(frozen=True, slots=True)
class MaterializedVerification:
    ok: bool
    code: str


@dataclass(frozen=True, slots=True)
class MaterializedMergeOutcome:
    merged_state: Json
    accepted_lane_ids: tuple[str, ...]
    serialized_lane_ids: tuple[str, ...]


def _canon_paths(values: list[str] | tuple[str, ...]) -> tuple[str, ...]:
    out: list[str] = []
    seen: set[str] = set()
    for item in values:
        s = str(item or "").strip()
        if not s or s in seen:
            continue
        seen.add(s)
        out.append(s)
    out.sort()
    return tuple(out)


def _canon_delta_ops(delta_ops: list[HelperDeltaOp] | tuple[HelperDeltaOp, ...]) -> tuple[Json, ...]:
    rows = [op.to_json() for op in delta_ops]
    rows.sort(key=lambda row: (str(row.get("path") or ""), str(row.get("op") or ""), hash_json(row)))
    return tuple(rows)


def _hash_delta_ops(delta_ops: list[HelperDeltaOp] | tuple[HelperDeltaOp, ...]) -> str:
    return hash_json(list(_canon_delta_ops(delta_ops)))


def verify_materialized_lane_result(result: MaterializedLaneResult) -> MaterializedVerification:
    cert = result.cert
    lane_plan = result.lane_plan
    if tuple(lane_plan.tx_ids) != tuple(cert.tx_ids):
        return MaterializedVerification(ok=False, code="tx_set_mismatch")
    if tuple(result.receipts) and cert.receipts_root != hash_receipts(list(result.receipts)):
        return MaterializedVerification(ok=False, code="receipts_root_mismatch")
    if cert.read_set_hash != hash_ordered_strings(list(_canon_paths(result.read_set))):
        return MaterializedVerification(ok=False, code="read_set_hash_mismatch")
    if cert.write_set_hash != hash_ordered_strings(list(_canon_paths(result.write_set))):
        return MaterializedVerification(ok=False, code="write_set_hash_mismatch")
    if cert.lane_delta_hash != _hash_delta_ops(result.delta_ops):
        return MaterializedVerification(ok=False, code="lane_delta_hash_mismatch")
    if cert.namespace_hash != make_namespace_hash(list(result.namespace_prefixes)):
        return MaterializedVerification(ok=False, code="namespace_hash_mismatch")
    if not validate_certificate_scope(cert, namespace_prefixes=list(result.namespace_prefixes)):
        return MaterializedVerification(ok=False, code="namespace_scope_invalid")
    return MaterializedVerification(ok=True, code="ok")


def detect_materialized_overlap(results: list[MaterializedLaneResult]) -> tuple[bool, str]:
    all_writes: dict[str, str] = {}
    all_reads: dict[str, str] = {}
    for result in results:
        lane_id = str(result.cert.lane_id)
        for path in _canon_paths(result.write_set):
            other_write = all_writes.get(path)
            if other_write and other_write != lane_id:
                return True, f"write_write:{path}"
            other_read = all_reads.get(path)
            if other_read and other_read != lane_id:
                return True, f"write_read:{path}"
            all_writes[path] = lane_id
        for path in _canon_paths(result.read_set):
            other_write = all_writes.get(path)
            if other_write and other_write != lane_id:
                return True, f"read_write:{path}"
            all_reads[path] = lane_id
    return False, ""


def _set_path(root: Json, path: str, value: Any) -> None:
    parts = [p for p in str(path or "").split("/") if p]
    if not parts:
        raise ValueError("empty_path")
    cur: Any = root
    for part in parts[:-1]:
        nxt = cur.get(part)
        if not isinstance(nxt, dict):
            nxt = {}
            cur[part] = nxt
        cur = nxt
    cur[parts[-1]] = copy.deepcopy(value)


def _delete_path(root: Json, path: str) -> None:
    parts = [p for p in str(path or "").split("/") if p]
    if not parts:
        raise ValueError("empty_path")
    cur: Any = root
    for part in parts[:-1]:
        nxt = cur.get(part)
        if not isinstance(nxt, dict):
            return
        cur = nxt
    cur.pop(parts[-1], None)


def apply_materialized_delta_ops(state: Json, delta_ops: list[HelperDeltaOp] | tuple[HelperDeltaOp, ...]) -> Json:
    out: Json = copy.deepcopy(state)
    for op in _canon_delta_ops(delta_ops):
        op_name = str(op.get("op") or "")
        path = str(op.get("path") or "")
        if op_name == "set":
            _set_path(out, path, op.get("value"))
            continue
        if op_name == "delete":
            _delete_path(out, path)
            continue
        raise ValueError(f"unsupported_delta_op:{op_name}")
    return out


def merge_materialized_lane_results(
    *,
    base_state: Json,
    lane_results: list[MaterializedLaneResult],
) -> MaterializedMergeOutcome:
    verified: list[MaterializedLaneResult] = []
    serialized: list[str] = []
    for result in sorted(lane_results, key=lambda item: (item.cert.lane_id, list(item.cert.tx_ids))):
        status = verify_materialized_lane_result(result)
        if not status.ok:
            serialized.append(str(result.cert.lane_id))
            continue
        verified.append(result)
    overlap, _reason = detect_materialized_overlap(verified)
    if overlap:
        return MaterializedMergeOutcome(
            merged_state=copy.deepcopy(base_state),
            accepted_lane_ids=tuple(),
            serialized_lane_ids=tuple(sorted({str(r.cert.lane_id) for r in lane_results})),
        )
    merged = copy.deepcopy(base_state)
    accepted: list[str] = []
    for result in sorted(verified, key=lambda item: (item.cert.lane_id, list(item.cert.tx_ids))):
        merged = apply_materialized_delta_ops(merged, result.delta_ops)
        accepted.append(str(result.cert.lane_id))
    return MaterializedMergeOutcome(
        merged_state=merged,
        accepted_lane_ids=tuple(accepted),
        serialized_lane_ids=tuple(sorted(set(serialized))),
    )
