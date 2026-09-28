from __future__ import annotations

import copy
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from weall.runtime.helper_certificates import (
    HelperExecutionCertificate,
    ensure_helper_execution_certificate,
    hash_json,
    hash_ordered_strings,
    hash_receipts,
    make_namespace_hash,
    make_tx_order_hash,
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


def _canon_delta_ops(
    delta_ops: list[HelperDeltaOp] | tuple[HelperDeltaOp, ...],
) -> tuple[Json, ...]:
    rows = [op.to_json() for op in delta_ops]
    rows.sort(
        key=lambda row: (str(row.get("path") or ""), str(row.get("op") or ""), hash_json(row))
    )
    return tuple(rows)


def _hash_delta_ops(delta_ops: list[HelperDeltaOp] | tuple[HelperDeltaOp, ...]) -> str:
    return hash_json(list(_canon_delta_ops(delta_ops)))


def _canonical_namespace_prefixes(values: Sequence[str]) -> tuple[str, ...]:
    return tuple(
        sorted({str(item or "").strip().lower() for item in values if str(item or "").strip()})
    )


def _planned_access_scope(lane_plan: LanePlan) -> tuple[tuple[str, ...], tuple[str, ...]] | None:
    access_sets = tuple(lane_plan.access_sets or ())
    access_tx_ids = tuple(str(item.tx_id) for item in access_sets)
    expected_tx_ids = tuple(str(tx_id) for tx_id in lane_plan.tx_ids)
    if access_tx_ids != expected_tx_ids:
        return None
    reads = _canon_paths([path for item in access_sets for path in item.reads])
    writes = _canon_paths([path for item in access_sets for path in item.writes])
    return reads, writes


def _namespace_prefix_contains(prefix: str, key: str) -> bool:
    prefix2 = str(prefix or "").strip().lower()
    key2 = str(key or "").strip().lower()
    if not prefix2 or not key2:
        return False
    if key2 == prefix2:
        return True
    if prefix2.endswith((":", "/")):
        return key2.startswith(prefix2)
    return key2.startswith(f"{prefix2}:") or key2.startswith(f"{prefix2}/")


def _receipt_tx_ids(receipts: Sequence[Mapping[str, Any]]) -> tuple[str, ...]:
    return tuple(str(item.get("tx_id", "")) for item in receipts)


def _delta_op_scope_key(path: str) -> tuple[str, str]:
    raw = str(path or "").strip()
    if not raw:
        return "", ""
    if raw.startswith("namespaced/"):
        return "namespaced", raw[len("namespaced/") :].strip()
    return "legacy", raw


def _delta_ops_scope_status(
    *,
    namespace_prefixes: tuple[str, ...],
    write_set: tuple[str, ...],
    delta_ops: tuple[HelperDeltaOp, ...],
) -> str:
    allowed_prefixes = tuple(
        str(item or "").strip().lower() for item in namespace_prefixes if str(item or "").strip()
    )
    allowed_writes = set(_canon_paths(write_set))
    seen_paths: set[tuple[str, str]] = set()
    for op in delta_ops:
        mode, key = _delta_op_scope_key(op.path)
        if not key:
            return "delta_path_invalid"
        seen_key = (mode, key)
        if seen_key in seen_paths:
            return "delta_path_duplicate"
        if mode == "namespaced":
            lowered = key.lower()
            if not any(_namespace_prefix_contains(prefix, lowered) for prefix in allowed_prefixes):
                return "delta_namespace_scope_invalid"
            if key not in allowed_writes:
                return "delta_write_scope_mismatch"
            seen_paths.add(seen_key)
            continue
        if mode == "legacy":
            if key not in allowed_writes:
                return "delta_write_scope_mismatch"
            seen_paths.add(seen_key)
            continue
        return "delta_path_invalid"
    return "ok"


def verify_materialized_lane_result(
    result: MaterializedLaneResult,
    *,
    expected_lane_plan: LanePlan,
    accepted_certificate: HelperExecutionCertificate | Mapping[str, Any],
) -> MaterializedVerification:
    """Verify materialized helper output against coordinator-local authority.

    ``expected_lane_plan`` must be the coordinator's locally reconstructed plan,
    and ``accepted_certificate`` must be the certificate previously accepted by
    authenticated helper dispatch for that lane.  The helper-supplied result is
    never allowed to define its own authorization scope.
    """

    cert = result.cert
    lane_plan = expected_lane_plan
    accepted = ensure_helper_execution_certificate(accepted_certificate)

    if result.lane_plan != lane_plan:
        return MaterializedVerification(ok=False, code="lane_plan_mismatch")
    if accepted.to_json() != cert.to_json():
        return MaterializedVerification(ok=False, code="accepted_certificate_mismatch")

    lane_id = str(lane_plan.lane_id or "")
    if not lane_id or lane_id != str(cert.lane_id or ""):
        return MaterializedVerification(ok=False, code="lane_id_mismatch")
    expected_helper_id = str(lane_plan.helper_id or "")
    if not expected_helper_id:
        return MaterializedVerification(ok=False, code="helper_unassigned")
    if str(cert.helper_id or "") != expected_helper_id:
        return MaterializedVerification(ok=False, code="helper_id_mismatch")

    expected_tx_ids = tuple(str(tx_id) for tx_id in lane_plan.tx_ids)
    if expected_tx_ids != tuple(str(tx_id) for tx_id in cert.tx_ids):
        return MaterializedVerification(ok=False, code="tx_set_mismatch")
    if str(cert.tx_order_hash or "") != make_tx_order_hash(expected_tx_ids):
        return MaterializedVerification(ok=False, code="tx_order_hash_mismatch")
    if _receipt_tx_ids(result.receipts) != expected_tx_ids:
        return MaterializedVerification(ok=False, code="receipt_tx_order_mismatch")
    if cert.receipts_root != hash_receipts(list(result.receipts)):
        return MaterializedVerification(ok=False, code="receipts_root_mismatch")

    planned_scope = _planned_access_scope(lane_plan)
    if planned_scope is None:
        return MaterializedVerification(ok=False, code="lane_plan_access_tx_mismatch")
    expected_reads, expected_writes = planned_scope
    if _canon_paths(result.read_set) != expected_reads:
        return MaterializedVerification(ok=False, code="read_set_plan_mismatch")
    if _canon_paths(result.write_set) != expected_writes:
        return MaterializedVerification(ok=False, code="write_set_plan_mismatch")
    if cert.read_set_hash != hash_ordered_strings(list(expected_reads)):
        return MaterializedVerification(ok=False, code="read_set_hash_mismatch")
    if cert.write_set_hash != hash_ordered_strings(list(expected_writes)):
        return MaterializedVerification(ok=False, code="write_set_hash_mismatch")

    expected_namespaces = _canonical_namespace_prefixes(lane_plan.namespace_prefixes)
    observed_namespaces = _canonical_namespace_prefixes(result.namespace_prefixes)
    if observed_namespaces != expected_namespaces:
        return MaterializedVerification(ok=False, code="namespace_plan_mismatch")
    if cert.namespace_hash != make_namespace_hash(expected_namespaces):
        return MaterializedVerification(ok=False, code="namespace_hash_mismatch")
    if not validate_certificate_scope(cert, namespace_prefixes=list(expected_namespaces)):
        return MaterializedVerification(ok=False, code="namespace_scope_invalid")

    delta_scope_status = _delta_ops_scope_status(
        namespace_prefixes=expected_namespaces,
        write_set=expected_writes,
        delta_ops=tuple(result.delta_ops),
    )
    if delta_scope_status != "ok":
        return MaterializedVerification(ok=False, code=delta_scope_status)
    if cert.lane_delta_hash != _hash_delta_ops(result.delta_ops):
        return MaterializedVerification(ok=False, code="lane_delta_hash_mismatch")
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


def apply_materialized_delta_ops(
    state: Json, delta_ops: list[HelperDeltaOp] | tuple[HelperDeltaOp, ...]
) -> Json:
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
    lane_plans: Sequence[LanePlan],
    accepted_certificates: Mapping[str, HelperExecutionCertificate | Mapping[str, Any]],
) -> MaterializedMergeOutcome:
    """Merge only results bound to local plans and authenticated certificates.

    ``lane_plans`` is the coordinator-local set of lanes expected to materialize.
    Missing or invalid lanes are returned as serialized so a caller with a serial
    executor can replay them.  Unknown or duplicate result lanes fail the entire
    materialized merge closed because they indicate an ambiguous coordinator/helper
    boundary.
    """

    local_plans = tuple(lane_plans or ())
    plan_by_id: dict[str, LanePlan] = {}
    duplicate_plan_ids: set[str] = set()
    for plan in local_plans:
        lane_id = str(plan.lane_id or "")
        if not lane_id or lane_id in plan_by_id:
            duplicate_plan_ids.add(lane_id)
            continue
        plan_by_id[lane_id] = plan

    expected_lane_ids = set(plan_by_id)
    if duplicate_plan_ids:
        serialized = expected_lane_ids | {lane_id for lane_id in duplicate_plan_ids if lane_id}
        return MaterializedMergeOutcome(
            merged_state=copy.deepcopy(base_state),
            accepted_lane_ids=tuple(),
            serialized_lane_ids=tuple(sorted(serialized)),
        )

    result_by_id: dict[str, MaterializedLaneResult] = {}
    duplicate_result_ids: set[str] = set()
    unknown_result_ids: set[str] = set()
    for result in list(lane_results or []):
        lane_id = str(result.cert.lane_id or "")
        if lane_id not in plan_by_id:
            unknown_result_ids.add(lane_id)
            continue
        if lane_id in result_by_id:
            duplicate_result_ids.add(lane_id)
            continue
        result_by_id[lane_id] = result

    if duplicate_result_ids or unknown_result_ids:
        serialized = expected_lane_ids | {lane_id for lane_id in unknown_result_ids if lane_id}
        return MaterializedMergeOutcome(
            merged_state=copy.deepcopy(base_state),
            accepted_lane_ids=tuple(),
            serialized_lane_ids=tuple(sorted(serialized)),
        )

    verified: list[MaterializedLaneResult] = []
    serialized: set[str] = set(expected_lane_ids - set(result_by_id))
    for lane_id in sorted(expected_lane_ids):
        result = result_by_id.get(lane_id)
        if result is None:
            continue
        accepted_certificate = accepted_certificates.get(lane_id)
        if accepted_certificate is None:
            serialized.add(lane_id)
            continue
        status = verify_materialized_lane_result(
            result,
            expected_lane_plan=plan_by_id[lane_id],
            accepted_certificate=accepted_certificate,
        )
        if not status.ok:
            serialized.add(lane_id)
            continue
        verified.append(result)

    overlap, _reason = detect_materialized_overlap(verified)
    if overlap:
        return MaterializedMergeOutcome(
            merged_state=copy.deepcopy(base_state),
            accepted_lane_ids=tuple(),
            serialized_lane_ids=tuple(sorted(expected_lane_ids)),
        )

    merged = copy.deepcopy(base_state)
    accepted: list[str] = []
    for result in sorted(verified, key=lambda item: (item.cert.lane_id, list(item.cert.tx_ids))):
        merged = apply_materialized_delta_ops(merged, result.delta_ops)
        accepted.append(str(result.cert.lane_id))
    return MaterializedMergeOutcome(
        merged_state=merged,
        accepted_lane_ids=tuple(accepted),
        serialized_lane_ids=tuple(sorted(serialized)),
    )
