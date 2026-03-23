from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Mapping, Sequence

from weall.runtime.conflict_lanes import lane_base_id
from weall.runtime.helper_assignment import (
    assign_helper_candidates_for_lane,
    assign_helper_for_lane,
    choose_helper_from_candidates,
    compute_lane_cost_units,
    normalize_validators,
)
from weall.runtime.helper_capabilities import (
    filter_helper_candidates_by_capability,
    lane_class_for_plan,
    normalize_helper_capability_map,
)
from weall.runtime.helper_capacity import normalize_helper_capacity_map
from weall.runtime.helper_certificates import (
    HelperExecutionCertificate,
    ensure_helper_execution_certificate,
    hash_receipts,
    hash_state_delta_ops,
    make_namespace_hash,
)
from weall.runtime.lane_assignment import assign_execution_lane
from weall.runtime.read_write_sets import (
    CONTENT_LANE,
    ECONOMICS_LANE,
    GOVERNANCE_LANE,
    IDENTITY_LANE,
    SERIAL_LANE,
    SOCIAL_LANE,
    STORAGE_LANE,
    TxAccessSet,
    build_tx_access_set,
)

Json = dict[str, Any]

def _canonical_json(value: Any) -> str:
    import json
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def lane_descriptor_hash(access_sets: Sequence[TxAccessSet]) -> str:
    from hashlib import sha256
    material = [
        {
            "tx_id": str(item.tx_id),
            "reads": list(item.reads),
            "writes": list(item.writes),
            "family": str(item.family),
            "barrier_class": str(item.barrier_class),
            "authority_keys": list(item.authority_keys),
            "subject_keys": list(item.subject_keys),
        }
        for item in access_sets
    ]
    return sha256(_canonical_json(material).encode("utf-8")).hexdigest() if material else ""


def canonical_lane_plan_fingerprint(lane_plans: Sequence[LanePlan]) -> str:
    from hashlib import sha256
    material = [
        {
            "lane_id": str(plan.lane_id),
            "helper_id": str(plan.helper_id or ""),
            "tx_ids": list(plan.tx_ids),
            "descriptor_hash": str(plan.descriptor_hash or lane_descriptor_hash(plan.access_sets)),
        }
        for plan in sorted(tuple(lane_plans or ()), key=lambda item: item.lane_id)
    ]
    return sha256(_canonical_json(material).encode("utf-8")).hexdigest() if material else ""


@dataclass(frozen=True)
class LanePlan:
    lane_id: str
    helper_id: str | None
    txs: tuple[Json, ...]
    tx_ids: tuple[str, ...]
    access_sets: tuple[TxAccessSet, ...] = field(default_factory=tuple)
    namespace_prefixes: tuple[str, ...] = field(default_factory=tuple)
    helper_candidates: tuple[str, ...] = field(default_factory=tuple)
    original_helper_id: str | None = None
    rerouted_from_helper_id: str | None = None
    routing_mode: str = "serial"
    lane_class: str = "serial"
    lane_tx_types: tuple[str, ...] = field(default_factory=tuple)
    capability_restricted: bool = False
    lane_cost_units: int = 1
    helper_capacity_units: int = 0
    descriptor_hash: str = ""


@dataclass(frozen=True)
class LaneDecision:
    lane_id: str
    used_helper: bool
    fallback_reason: str | None = None
    tx_ids: tuple[str, ...] = field(default_factory=tuple)


@dataclass(frozen=True)
class MergeHelperLaneResults:
    receipts: list[Json]
    lane_decisions: tuple[LaneDecision, ...]


@dataclass(frozen=True)
class SerialHelperEquivalenceReport:
    ok: bool
    reason: str
    serial_receipts: tuple[Json, ...]
    helper_receipts: tuple[Json, ...]
    serial_tx_ids: tuple[str, ...]
    helper_tx_ids: tuple[str, ...]


def _canonical_tx_id(tx: Mapping[str, Any]) -> str:
    return str(tx.get("tx_id", ""))


def _tx_type(tx: Mapping[str, Any]) -> str:
    return str(tx.get("tx_type") or tx.get("type") or "").strip().upper()


def _tx_namespace_prefixes(tx: Mapping[str, Any], access: TxAccessSet) -> tuple[str, ...]:
    explicit = tx.get("state_prefixes")
    if isinstance(explicit, (list, tuple, set)):
        cleaned = tuple(sorted({str(v) for v in explicit if isinstance(v, str) and v.strip()}))
        if cleaned:
            return cleaned
    return tuple(sorted(set(access.reads) | set(access.writes)))


def _uses_explicit_access_sets(txs: Sequence[Json]) -> bool:
    return any("read_set" in tx or "write_set" in tx for tx in txs)


def _explicit_lane_override(tx: Mapping[str, Any], access: TxAccessSet) -> TxAccessSet:
    if access.lane_hint != SERIAL_LANE or access.fail_closed_serial:
        return access
    tx_type = _tx_type(tx)
    override = ""
    if tx_type.startswith(("CONTENT_", "INDEXING_")):
        override = CONTENT_LANE
    elif tx_type.startswith(("IDENTITY_", "POH_")):
        override = IDENTITY_LANE
    elif tx_type.startswith(("SOCIAL_", "REPUTATION_", "NOTIFICATION_", "MESSAGING_")):
        override = SOCIAL_LANE
    elif tx_type.startswith(("ECONOMICS_", "TREASURY_", "REWARDS_")):
        override = ECONOMICS_LANE
    elif tx_type.startswith("STORAGE_"):
        override = STORAGE_LANE
    elif tx_type.startswith(("GOV_", "GROUP_", "ROLE_")):
        override = GOVERNANCE_LANE
    if not override:
        return access
    return TxAccessSet(
        tx_id=access.tx_id,
        lane_hint=override,
        reads=access.reads,
        writes=access.writes,
        fail_closed_serial=access.fail_closed_serial,
    )


def _access_conflicts(existing: Sequence[TxAccessSet], access: TxAccessSet) -> bool:
    reads = set(access.reads)
    writes = set(access.writes)
    for item in existing:
        existing_reads = set(item.reads)
        existing_writes = set(item.writes)
        if existing_writes & writes:
            return True
        if existing_writes & reads:
            return True
        if existing_reads & writes:
            return True
    return False


def _plan_helper_assignment(
    *,
    lane_id: str,
    normalized_validators: Sequence[str],
    validator_set_hash: str,
    view: int,
    leader_id: str,
    quarantined_helpers: Sequence[str] | None,
    assignment_counts: Mapping[str, int],
    assignment_load_units: Mapping[str, int],
    helper_capacity_by_helper: Mapping[str, int],
    helper_capabilities_by_helper: Mapping[str, Any],
    lane_cost_units: int,
    lane_class: str,
    lane_tx_types: Sequence[str],
    allow_overcommit: bool,
) -> tuple[str | None, tuple[str, ...], str | None, str | None, str, int, bool]:
    candidates = assign_helper_candidates_for_lane(
        validators_normalized=list(normalized_validators or []),
        validator_set_hash=str(validator_set_hash or ""),
        view=int(view),
        lane_id=str(lane_id),
        leader_id=str(leader_id),
        quarantined_helpers=tuple(str(v) for v in list(quarantined_helpers or [])),
    )
    if str(lane_id) == SERIAL_LANE:
        return None, (), None, None, "serial", 0, False

    capability_candidates = filter_helper_candidates_by_capability(
        candidates,
        helper_capability_by_helper=helper_capabilities_by_helper,
        lane_class=lane_class,
        tx_types=lane_tx_types,
        lane_cost_units=lane_cost_units,
    )
    capability_restricted = capability_candidates != tuple(candidates)
    if not capability_candidates:
        return None, tuple(candidates), None, None, "capability_miss", 0, capability_restricted

    chosen = choose_helper_from_candidates(
        capability_candidates,
        assignment_counts=assignment_counts,
        assignment_load_units=assignment_load_units,
        helper_capacity_by_helper=helper_capacity_by_helper,
        lane_cost=int(lane_cost_units),
        quarantined_helpers=tuple(str(v) for v in list(quarantined_helpers or [])),
        allow_overcommit=bool(allow_overcommit),
    )
    if not chosen:
        return None, tuple(capability_candidates), None, None, "serial_capacity_fallback", 0, capability_restricted

    original_helper_id = str(capability_candidates[0]) if capability_candidates else str(chosen)
    rerouted_from = original_helper_id if chosen != original_helper_id else None
    capacity_units = int(helper_capacity_by_helper.get(str(chosen), 0))
    if capacity_units > 0 and (int(assignment_load_units.get(str(chosen), 0)) + int(lane_cost_units)) > capacity_units:
        routing_mode = "helper_overcommit"
    elif rerouted_from:
        routing_mode = "helper_load_balanced"
    else:
        routing_mode = "helper_primary"
    if capability_restricted and routing_mode == "helper_primary":
        routing_mode = "helper_capability_primary"
    elif capability_restricted and routing_mode == "helper_load_balanced":
        routing_mode = "helper_capability_rerouted"
    elif capability_restricted and routing_mode == "helper_overcommit":
        routing_mode = "helper_capability_overcommit"
    return str(chosen), tuple(capability_candidates), original_helper_id, rerouted_from, routing_mode, capacity_units, capability_restricted




def _helper_capacity_inputs(state_snapshot_metadata: Mapping[str, Any] | None) -> tuple[dict[str, int], dict[str, int], bool, dict[str, Json]]:
    metadata = dict(state_snapshot_metadata or {})
    helper_capacity = normalize_helper_capacity_map(metadata.get("helper_capacity_by_helper"))
    lane_cost_overrides_raw = metadata.get("helper_lane_cost_overrides")
    lane_cost_overrides: dict[str, int] = {}
    if isinstance(lane_cost_overrides_raw, Mapping):
        for lane_id, raw in dict(lane_cost_overrides_raw).items():
            lid = str(lane_id or "").strip()
            if not lid:
                continue
            try:
                lane_cost_overrides[lid] = max(1, int(raw))
            except Exception:
                continue
    allow_overcommit = bool(metadata.get("allow_helper_overcommit", True))
    helper_capabilities = normalize_helper_capability_map(metadata.get("helper_capabilities_by_helper"))
    return helper_capacity, lane_cost_overrides, allow_overcommit, helper_capabilities

def _parallel_lane_groups(
    txs: Sequence[Json],
    *,
    validators: Sequence[str],
    validator_set_hash: str,
    view: int,
    leader_id: str,
    quarantined_helpers: Sequence[str] | None = None,
    state_snapshot_metadata: Mapping[str, Any] | None = None,
) -> tuple[LanePlan, ...]:
    normalized_validators = normalize_validators(list(validators or []))
    plans: list[LanePlan] = []
    assignment_counts: dict[str, int] = {}
    assignment_load_units: dict[str, int] = {}
    helper_capacity_by_helper, lane_cost_overrides, allow_overcommit, helper_capabilities_by_helper = _helper_capacity_inputs(state_snapshot_metadata)

    current_lane_id: str | None = None
    current_txs: list[Json] = []
    current_access: list[TxAccessSet] = []
    current_namespaces: list[str] = []

    def flush() -> None:
        nonlocal current_lane_id, current_txs, current_access, current_namespaces
        if current_lane_id is None or not current_txs:
            current_lane_id = None
            current_txs = []
            current_access = []
            current_namespaces = []
            return
        lane_cost_units = compute_lane_cost_units(
            lane_id=str(current_lane_id),
            tx_count=len(current_txs),
            namespace_prefixes=tuple(sorted({p for p in current_namespaces if p})),
            override_units=lane_cost_overrides.get(str(current_lane_id)),
        )
        lane_tx_types = tuple(sorted({_tx_type(tx) for tx in current_txs if _tx_type(tx)}))
        lane_class = lane_class_for_plan(lane_id=str(current_lane_id), tx_types=lane_tx_types)
        helper_id, helper_candidates, original_helper_id, rerouted_from_helper_id, routing_mode, helper_capacity_units, capability_restricted = _plan_helper_assignment(
            lane_id=str(current_lane_id),
            normalized_validators=normalized_validators,
            validator_set_hash=validator_set_hash,
            view=int(view),
            leader_id=str(leader_id),
            quarantined_helpers=quarantined_helpers,
            assignment_counts=assignment_counts,
            assignment_load_units=assignment_load_units,
            helper_capacity_by_helper=helper_capacity_by_helper,
            helper_capabilities_by_helper=helper_capabilities_by_helper,
            lane_cost_units=lane_cost_units,
            lane_class=lane_class,
            lane_tx_types=lane_tx_types,
            allow_overcommit=allow_overcommit,
        )
        if helper_id:
            assignment_counts[str(helper_id)] = int(assignment_counts.get(str(helper_id), 0)) + 1
            assignment_load_units[str(helper_id)] = int(assignment_load_units.get(str(helper_id), 0)) + int(lane_cost_units)
        plans.append(
            LanePlan(
                lane_id=current_lane_id,
                helper_id=helper_id,
                txs=tuple(dict(tx) for tx in current_txs),
                tx_ids=tuple(_canonical_tx_id(tx) for tx in current_txs),
                access_sets=tuple(current_access),
                namespace_prefixes=tuple(sorted({p for p in current_namespaces if p})),
                helper_candidates=tuple(helper_candidates),
                original_helper_id=original_helper_id,
                rerouted_from_helper_id=rerouted_from_helper_id,
                routing_mode=routing_mode,
                lane_class=str(lane_class),
                lane_tx_types=tuple(lane_tx_types),
                capability_restricted=bool(capability_restricted),
                lane_cost_units=int(lane_cost_units),
                helper_capacity_units=int(helper_capacity_units),
                descriptor_hash=lane_descriptor_hash(tuple(current_access)),
            )
        )
        current_lane_id = None
        current_txs = []
        current_access = []
        current_namespaces = []

    for tx in list(txs or []):
        txj = dict(tx)
        lane_id = assign_execution_lane(txj, None)
        access = build_tx_access_set(txj)
        namespaces = list(_tx_namespace_prefixes(txj, access))
        if current_lane_id is None:
            current_lane_id = lane_id
        elif lane_id != current_lane_id:
            flush()
            current_lane_id = lane_id
        current_txs.append(txj)
        current_access.append(access)
        current_namespaces.extend(namespaces)
    flush()
    return tuple(plans)


def _explicit_lane_groups(
    txs: Sequence[Json],
    *,
    validators: Sequence[str],
    validator_set_hash: str,
    view: int,
    leader_id: str,
    quarantined_helpers: Sequence[str] | None = None,
    state_snapshot_metadata: Mapping[str, Any] | None = None,
) -> tuple[LanePlan, ...]:
    normalized_validators = normalize_validators(list(validators or []))
    access_sets = [_explicit_lane_override(tx, build_tx_access_set(tx)) for tx in txs]
    plans: list[LanePlan] = []
    lane_counters: dict[str, int] = {}
    assignment_counts: dict[str, int] = {}
    assignment_load_units: dict[str, int] = {}
    helper_capacity_by_helper, lane_cost_overrides, allow_overcommit, helper_capabilities_by_helper = _helper_capacity_inputs(state_snapshot_metadata)

    current_base: str | None = None
    current_tx_type: str | None = None
    current_txs: list[Json] = []
    current_access: list[TxAccessSet] = []
    current_namespaces: list[str] = []

    def flush() -> None:
        nonlocal current_base, current_tx_type, current_txs, current_access, current_namespaces
        if current_base is None or not current_txs:
            current_base = None
            current_tx_type = None
            current_txs = []
            current_access = []
            current_namespaces = []
            return
        lane_index = lane_counters.get(current_base, 0)
        lane_counters[current_base] = lane_index + 1
        lane_id = current_base if lane_index == 0 else f"{current_base}#{lane_index}"
        lane_cost_units = compute_lane_cost_units(
            lane_id=str(lane_id),
            tx_count=len(current_txs),
            namespace_prefixes=tuple(sorted({p for p in current_namespaces if p})),
            override_units=lane_cost_overrides.get(str(lane_id)),
        )
        lane_tx_types = tuple(sorted({_tx_type(tx) for tx in current_txs if _tx_type(tx)}))
        lane_class = lane_class_for_plan(lane_id=str(lane_id), tx_types=lane_tx_types)
        helper_id, helper_candidates, original_helper_id, rerouted_from_helper_id, routing_mode, helper_capacity_units, capability_restricted = _plan_helper_assignment(
            lane_id=str(lane_id),
            normalized_validators=normalized_validators,
            validator_set_hash=validator_set_hash,
            view=int(view),
            leader_id=str(leader_id),
            quarantined_helpers=quarantined_helpers,
            assignment_counts=assignment_counts,
            assignment_load_units=assignment_load_units,
            helper_capacity_by_helper=helper_capacity_by_helper,
            helper_capabilities_by_helper=helper_capabilities_by_helper,
            lane_cost_units=lane_cost_units,
            lane_class=lane_class,
            lane_tx_types=lane_tx_types,
            allow_overcommit=allow_overcommit,
        )
        if helper_id:
            assignment_counts[str(helper_id)] = int(assignment_counts.get(str(helper_id), 0)) + 1
            assignment_load_units[str(helper_id)] = int(assignment_load_units.get(str(helper_id), 0)) + int(lane_cost_units)
        plans.append(
            LanePlan(
                lane_id=lane_id,
                helper_id=helper_id,
                txs=tuple(current_txs),
                tx_ids=tuple(access.tx_id for access in current_access),
                access_sets=tuple(current_access),
                namespace_prefixes=tuple(sorted({p for p in current_namespaces if p})),
                helper_candidates=tuple(helper_candidates),
                original_helper_id=original_helper_id,
                rerouted_from_helper_id=rerouted_from_helper_id,
                routing_mode=routing_mode,
                lane_class=str(lane_class),
                lane_tx_types=tuple(lane_tx_types),
                capability_restricted=bool(capability_restricted),
                lane_cost_units=int(lane_cost_units),
                helper_capacity_units=int(helper_capacity_units),
                descriptor_hash=lane_descriptor_hash(tuple(current_access)),
            )
        )
        current_base = None
        current_tx_type = None
        current_txs = []
        current_access = []
        current_namespaces = []

    for tx, access in zip(txs, access_sets):
        base = SERIAL_LANE if access.fail_closed_serial else lane_base_id(access.lane_hint)
        tx_type = _tx_type(tx)
        if current_base is None:
            current_base = base
            current_tx_type = tx_type
        elif base != current_base or tx_type != current_tx_type or _access_conflicts(current_access, access):
            flush()
            current_base = base
            current_tx_type = tx_type
        current_txs.append(dict(tx))
        current_access.append(access)
        current_namespaces.extend(_tx_namespace_prefixes(tx, access))

    flush()
    return tuple(plans)


def plan_parallel_execution(
    *,
    txs: list[Json],
    validators: list[str],
    validator_set_hash: str,
    view: int,
    leader_id: str,
    state_snapshot_metadata: Json | None = None,
) -> tuple[LanePlan, ...]:
    snapshot = dict(state_snapshot_metadata or {})
    quarantined_helpers = tuple(str(v) for v in list(snapshot.get("quarantined_helper_ids") or []))
    txs2 = [dict(tx) for tx in list(txs or [])]
    if not txs2:
        return ()
    if _uses_explicit_access_sets(txs2):
        return _explicit_lane_groups(
            txs2,
            validators=validators,
            validator_set_hash=validator_set_hash,
            view=view,
            leader_id=leader_id,
            quarantined_helpers=quarantined_helpers,
            state_snapshot_metadata=snapshot,
        )
    return _parallel_lane_groups(
        txs2,
        validators=validators,
        validator_set_hash=validator_set_hash,
        view=view,
        leader_id=leader_id,
        quarantined_helpers=quarantined_helpers,
        state_snapshot_metadata=snapshot,
    )


def _serial_execute_lane(
    lane_txs: Sequence[Json],
    serial_executor: Callable[..., Any],
    leader_context: Mapping[str, Any],
) -> list[Json]:
    try:
        out = serial_executor(list(lane_txs), dict(leader_context))
    except TypeError:
        out = serial_executor(list(lane_txs))
    if isinstance(out, tuple):
        out = out[0]
    return [dict(item) for item in list(out or [])]


def _cert_namespace_valid(cert: HelperExecutionCertificate, plan: LanePlan) -> bool:
    return cert.namespace_hash == make_namespace_hash(plan.namespace_prefixes)


def _helper_receipts_valid(lane_receipts: Sequence[Mapping[str, Any]], plan: LanePlan) -> bool:
    observed_ids = [str(item.get("tx_id", "")) for item in lane_receipts]
    return observed_ids == list(plan.tx_ids)


def _helper_receipts_root_valid(cert: HelperExecutionCertificate, lane_receipts: Sequence[Mapping[str, Any]]) -> bool:
    return str(cert.receipts_root or "") == hash_receipts(lane_receipts)


def _helper_state_delta_hash_valid(
    cert: HelperExecutionCertificate,
    lane_delta_ops: Sequence[Mapping[str, Any]],
) -> bool:
    return str(cert.lane_delta_hash or "") == hash_state_delta_ops(lane_delta_ops)



def canonical_helper_execution_plan_fingerprint(lanes: Sequence[Mapping[str, Any]] | None) -> str:
    from hashlib import sha256
    material = []
    for lane in sorted(tuple(lanes or ()), key=lambda item: str(getattr(item, 'get', lambda _k, _d=None: '')('lane_id') if isinstance(item, Mapping) else '')):
        if not isinstance(lane, Mapping):
            continue
        tx_ids = lane.get('tx_ids')
        if not isinstance(tx_ids, (list, tuple)):
            tx_ids = []
        descriptor_hash = str(lane.get('descriptor_hash') or '')
        material.append({
            'lane_id': str(lane.get('lane_id') or ''),
            'helper_id': str(lane.get('helper_id') or ''),
            'tx_ids': [str(tx_id) for tx_id in tx_ids],
            'descriptor_hash': descriptor_hash,
        })
    return sha256(_canonical_json(material).encode('utf-8')).hexdigest() if material else ''


def verify_block_helper_plan_metadata(
    *,
    helper_execution: Mapping[str, Any] | None,
    expected_plan_id: str = '',
) -> tuple[bool, str]:
    if not isinstance(helper_execution, Mapping):
        return True, 'ok'
    lanes = helper_execution.get('lanes')
    if not isinstance(lanes, list):
        return False, 'helper_execution_lanes_missing'
    computed_plan_id = canonical_helper_execution_plan_fingerprint(lanes)
    advertised_plan_id = str(helper_execution.get('plan_id') or expected_plan_id or '')
    if advertised_plan_id and computed_plan_id and advertised_plan_id != computed_plan_id:
        return False, 'helper_execution_plan_id_mismatch'
    if expected_plan_id and computed_plan_id and expected_plan_id != computed_plan_id:
        return False, 'helper_execution_expected_plan_id_mismatch'
    for lane in lanes:
        if not isinstance(lane, Mapping):
            return False, 'helper_execution_lane_bad_shape'
        lane_plan_id = str(lane.get('plan_id') or '')
        if advertised_plan_id and lane_plan_id and lane_plan_id != advertised_plan_id:
            return False, 'helper_execution_lane_plan_id_mismatch'
    accepted = helper_execution.get('accepted_certificates')
    if isinstance(accepted, list):
        for row in accepted:
            if not isinstance(row, Mapping):
                return False, 'helper_execution_certificate_bad_shape'
            cert_plan_id = str(row.get('plan_id') or '')
            if advertised_plan_id and cert_plan_id and cert_plan_id != advertised_plan_id:
                return False, 'helper_execution_certificate_plan_id_mismatch'
    return True, 'ok'

def _helper_state_delta_hash_valid(cert: HelperExecutionCertificate, lane_delta_ops: Sequence[Mapping[str, Any]]) -> bool:
    return str(cert.lane_delta_hash or "") == hash_state_delta_ops(tuple(dict(item) for item in lane_delta_ops))


def should_fallback_to_serial(
    *,
    plan: LanePlan,
    helper_certificate: HelperExecutionCertificate | Mapping[str, Any] | None,
    leader_context: Mapping[str, Any],
) -> tuple[bool, str | None]:
    if plan.lane_id == SERIAL_LANE:
        return True, "serial_lane"
    if not plan.helper_id:
        return True, "helper_unassigned"
    if helper_certificate is None:
        return True, "missing_helper_certificate"
    return False, None


def verify_lane_plan_equivalence(
    *,
    local_lane_plans: Sequence[LanePlan],
    remote_plan_id: str = "",
    remote_lane_plans: Sequence[LanePlan] | None = None,
) -> tuple[bool, str]:
    local_plan_id = canonical_lane_plan_fingerprint(tuple(local_lane_plans or ()))
    remote_plan_id2 = str(remote_plan_id or "")
    if remote_lane_plans is not None:
        remote_plan_id2 = canonical_lane_plan_fingerprint(tuple(remote_lane_plans or ()))
    if not local_plan_id:
        return False, "missing_local_plan"
    if not remote_plan_id2:
        return False, "missing_remote_plan"
    if local_plan_id != remote_plan_id2:
        return False, "plan_id_mismatch"
    return True, "ok"


def verify_vote_ready_helper_plan(
    *,
    local_lane_plans: Sequence[LanePlan],
    advertised_plan_id: str = "",
    helper_certificates: Mapping[str, HelperExecutionCertificate | Mapping[str, Any]] | None = None,
) -> tuple[bool, str]:
    ok, reason = verify_lane_plan_equivalence(
        local_lane_plans=local_lane_plans,
        remote_plan_id=str(advertised_plan_id or ""),
    )
    if not ok:
        return ok, reason
    expected_plan_id = canonical_lane_plan_fingerprint(tuple(local_lane_plans or ()))
    for lane_id, raw_cert in sorted(dict(helper_certificates or {}).items()):
        cert = ensure_helper_execution_certificate(raw_cert)
        cert_plan_id = str(getattr(cert, "plan_id", "") or "")
        if cert_plan_id and cert_plan_id != expected_plan_id:
            return False, f"certificate_plan_id_mismatch:{lane_id}"
    return True, "ok"
def verify_helper_certificate(
    *,
    cert: HelperExecutionCertificate | Mapping[str, Any],
    lane_plan: LanePlan,
    expected_helper_id: str,
    chain_id: str,
    block_height: int,
    view: int,
    leader_id: str,
    validator_epoch: int,
    validator_set_hash: str,
    manifest_hash: str = "",
    require_internal_consistency: bool = False,
    plan_id: str = "",
) -> tuple[bool, str]:
    normalized = ensure_helper_execution_certificate(cert)
    if normalized.chain_id != str(chain_id):
        return False, "chain_id_mismatch"
    if int(normalized.block_height) != int(block_height) or int(normalized.view) != int(view):
        return False, "stale_certificate"
    if normalized.leader_id != str(leader_id):
        return False, "leader_mismatch"
    if int(normalized.validator_epoch) != int(validator_epoch):
        return False, "epoch_mismatch"
    if normalized.validator_set_hash != str(validator_set_hash):
        return False, "validator_set_hash_mismatch"
    if normalized.helper_id != str(expected_helper_id or ""):
        return False, "wrong_helper"
    if bool(require_internal_consistency) and not normalized.verify_internal_consistency():
        return False, "helper_certificate_inconsistent"
    if str(manifest_hash or "") and str(normalized.manifest_hash or "") != str(manifest_hash):
        return False, "manifest_hash_mismatch"
    if str(plan_id or "") and str(getattr(normalized, "plan_id", "") or "") not in {"", str(plan_id)}:
        return False, "plan_id_mismatch"
    if normalized.lane_id != str(lane_plan.lane_id):
        return False, "lane_id_mismatch"
    if tuple(str(x) for x in normalized.tx_ids) != tuple(str(x) for x in lane_plan.tx_ids):
        return False, "tx_id_subset_mismatch"
    return True, "ok"


def merge_helper_lane_results(
    *,
    canonical_txs: Sequence[Json],
    lane_plans: Sequence[LanePlan],
    helper_certificates: Mapping[str, HelperExecutionCertificate | Mapping[str, Any]],
    serial_executor: Callable[..., Any],
    leader_context: Mapping[str, Any],
) -> MergeHelperLaneResults:
    del canonical_txs

    chain_id = str(leader_context.get("chain_id", ""))
    block_height = int(leader_context.get("block_height", 0))
    view = int(leader_context.get("view", 0))
    leader_id = str(leader_context.get("leader_id", ""))
    validator_epoch = int(leader_context.get("validator_epoch", 0))
    validator_set_hash = str(leader_context.get("validator_set_hash", ""))
    helper_receipts_by_lane = leader_context.get("helper_receipts", {})
    if not isinstance(helper_receipts_by_lane, Mapping):
        helper_receipts_by_lane = {}
    helper_state_deltas_by_lane = leader_context.get("helper_state_deltas", {})
    if not isinstance(helper_state_deltas_by_lane, Mapping):
        helper_state_deltas_by_lane = {}

    receipts: list[Json] = []
    decisions: list[LaneDecision] = []

    for plan in lane_plans:
        raw_cert = helper_certificates.get(plan.lane_id)
        should_fallback, fallback_reason = should_fallback_to_serial(
            plan=plan,
            helper_certificate=raw_cert,
            leader_context=leader_context,
        )
        if should_fallback:
            receipts.extend(_serial_execute_lane(plan.txs, serial_executor, leader_context))
            decisions.append(
                LaneDecision(
                    lane_id=plan.lane_id,
                    used_helper=False,
                    fallback_reason=fallback_reason,
                    tx_ids=tuple(str(tx_id) for tx_id in plan.tx_ids),
                )
            )
            continue

        cert = ensure_helper_execution_certificate(raw_cert)
        ok, reason = verify_helper_certificate(
            cert=cert,
            lane_plan=plan,
            expected_helper_id=str(plan.helper_id or ""),
            chain_id=chain_id,
            block_height=block_height,
            view=view,
            leader_id=leader_id,
            validator_epoch=validator_epoch,
            validator_set_hash=validator_set_hash,
            manifest_hash=str(leader_context.get("manifest_hash", "")),
            require_internal_consistency=bool(leader_context.get("enforce_helper_certificate_consistency", False)),
            plan_id=str(leader_context.get("plan_id", "")),
        )
        if not ok:
            receipts.extend(_serial_execute_lane(plan.txs, serial_executor, leader_context))
            decisions.append(LaneDecision(plan.lane_id, False, reason, tuple(str(tx_id) for tx_id in plan.tx_ids)))
            continue

        if not _cert_namespace_valid(cert, plan):
            receipts.extend(_serial_execute_lane(plan.txs, serial_executor, leader_context))
            decisions.append(LaneDecision(plan.lane_id, False, "namespace_scope_invalid", tuple(str(tx_id) for tx_id in plan.tx_ids)))
            continue

        lane_receipts = helper_receipts_by_lane.get(plan.lane_id)
        if not isinstance(lane_receipts, Sequence):
            receipts.extend(_serial_execute_lane(plan.txs, serial_executor, leader_context))
            decisions.append(LaneDecision(plan.lane_id, False, "missing_helper_receipts", tuple(str(tx_id) for tx_id in plan.tx_ids)))
            continue

        normalized_lane_receipts = [dict(item) for item in lane_receipts]
        if not _helper_receipts_valid(normalized_lane_receipts, plan):
            receipts.extend(_serial_execute_lane(plan.txs, serial_executor, leader_context))
            decisions.append(LaneDecision(plan.lane_id, False, "helper_receipts_invalid", tuple(str(tx_id) for tx_id in plan.tx_ids)))
            continue
        if bool(leader_context.get("enforce_helper_receipts_root", False)) and not _helper_receipts_root_valid(cert, normalized_lane_receipts):
            receipts.extend(_serial_execute_lane(plan.txs, serial_executor, leader_context))
            decisions.append(LaneDecision(plan.lane_id, False, "helper_receipts_root_mismatch", tuple(str(tx_id) for tx_id in plan.tx_ids)))
            continue

        if bool(leader_context.get("enforce_helper_state_delta_hash", False)):
            lane_delta_ops = helper_state_deltas_by_lane.get(plan.lane_id)
            if not isinstance(lane_delta_ops, Sequence):
                receipts.extend(_serial_execute_lane(plan.txs, serial_executor, leader_context))
                decisions.append(LaneDecision(plan.lane_id, False, "missing_helper_state_delta", tuple(str(tx_id) for tx_id in plan.tx_ids)))
                continue
            normalized_lane_delta_ops = [dict(item) for item in lane_delta_ops if isinstance(item, Mapping)]
            if not _helper_state_delta_hash_valid(cert, normalized_lane_delta_ops):
                receipts.extend(_serial_execute_lane(plan.txs, serial_executor, leader_context))
                decisions.append(LaneDecision(plan.lane_id, False, "helper_state_delta_hash_mismatch", tuple(str(tx_id) for tx_id in plan.tx_ids)))
                continue

        receipts.extend(normalized_lane_receipts)
        decisions.append(LaneDecision(plan.lane_id, True, None, tuple(str(tx_id) for tx_id in plan.tx_ids)))

    return MergeHelperLaneResults(receipts=receipts, lane_decisions=tuple(decisions))


def verify_serial_helper_equivalence(
    *,
    canonical_txs: Sequence[Json],
    lane_plans: Sequence[LanePlan],
    helper_certificates: Mapping[str, HelperExecutionCertificate],
    helper_receipts_by_lane: Mapping[str, Sequence[Mapping[str, Any]]],
    serial_executor: Callable[..., Any],
    leader_context: Mapping[str, Any],
) -> SerialHelperEquivalenceReport:
    serial_receipts = tuple(_serial_execute_lane(tuple(canonical_txs or ()), serial_executor, leader_context))
    helper_result = merge_helper_lane_results(
        canonical_txs=canonical_txs,
        lane_plans=lane_plans,
        helper_certificates=helper_certificates,
        serial_executor=serial_executor,
        leader_context={**dict(leader_context), "helper_receipts": dict(helper_receipts_by_lane or {})},
    )
    helper_receipts = tuple(dict(item) for item in helper_result.receipts)
    serial_tx_ids = tuple(str(item.get("tx_id", "")) for item in serial_receipts)
    helper_tx_ids = tuple(str(item.get("tx_id", "")) for item in helper_receipts)
    if serial_tx_ids != helper_tx_ids:
        return SerialHelperEquivalenceReport(
            ok=False,
            reason="tx_order_mismatch",
            serial_receipts=serial_receipts,
            helper_receipts=helper_receipts,
            serial_tx_ids=serial_tx_ids,
            helper_tx_ids=helper_tx_ids,
        )
    if serial_receipts != helper_receipts:
        return SerialHelperEquivalenceReport(
            ok=False,
            reason="receipt_mismatch",
            serial_receipts=serial_receipts,
            helper_receipts=helper_receipts,
            serial_tx_ids=serial_tx_ids,
            helper_tx_ids=helper_tx_ids,
        )
    return SerialHelperEquivalenceReport(
        ok=True,
        reason="ok",
        serial_receipts=serial_receipts,
        helper_receipts=helper_receipts,
        serial_tx_ids=serial_tx_ids,
        helper_tx_ids=helper_tx_ids,
    )


__all__ = [
    "LaneDecision",
    "LanePlan",
    "MergeHelperLaneResults",
    "lane_base_id",
    "merge_helper_lane_results",
    "plan_parallel_execution",
    "should_fallback_to_serial",
    "verify_serial_helper_equivalence",
    "SerialHelperEquivalenceReport",
    "verify_block_helper_plan_metadata",
    "verify_helper_certificate",
    "verify_lane_plan_equivalence",
    "canonical_helper_execution_plan_fingerprint",
    "verify_vote_ready_helper_plan",
]
