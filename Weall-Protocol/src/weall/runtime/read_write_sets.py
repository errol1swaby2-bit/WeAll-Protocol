from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Iterable

from .tx_conflicts import BarrierClass, TxFamily, build_conflict_descriptor, lane_hint_for_family


SERIAL_LANE = "SERIAL"
IDENTITY_LANE = "IDENTITY"
CONTENT_LANE = "CONTENT"
SOCIAL_LANE = "SOCIAL"
GOVERNANCE_LANE = "GOVERNANCE"
ECONOMICS_LANE = "ECONOMICS"
STORAGE_LANE = "STORAGE"


@dataclass(frozen=True)
class TxAccessSet:
    tx_id: str
    lane_hint: str
    reads: tuple[str, ...]
    writes: tuple[str, ...]
    fail_closed_serial: bool
    family: str = "UNKNOWN"
    barrier_class: str = "GLOBAL_BARRIER"
    subject_keys: tuple[str, ...] = ()
    authority_keys: tuple[str, ...] = ()
    derived_only: bool = False


def _sorted_unique_strs(values: Iterable[Any]) -> tuple[str, ...]:
    cleaned = {str(v) for v in values if isinstance(v, str) and v.strip()}
    return tuple(sorted(cleaned))


def _infer_lane_from_keys(keys: Iterable[str]) -> str:
    prefixes: set[str] = set()
    for key in keys:
        if key.startswith(("identity:", "poh:")):
            prefixes.add(IDENTITY_LANE)
        elif key.startswith(("content:", "index:")):
            prefixes.add(CONTENT_LANE)
        elif key.startswith(("social:", "reputation:", "notifications:", "messaging:", "performance:")):
            prefixes.add(SOCIAL_LANE)
        elif key.startswith(("gov:", "governance:", "roles:", "groups:", "dispute:", "cases:", "moderation:")):
            prefixes.add(GOVERNANCE_LANE)
        elif key.startswith(("economics:", "treasury:", "rewards:")):
            prefixes.add(ECONOMICS_LANE)
        elif key.startswith(("storage:", "ipfs:", "network:")):
            prefixes.add(STORAGE_LANE)
        elif key.startswith(("consensus:", "authority:", "barrier:")):
            # Authority/barrier namespaces are scope metadata, not their own lane.
            # Keep scanning other keys so explicit authority-bound txs can still
            # resolve to their family lane when the scoped writes are materialized.
            continue
        else:
            return SERIAL_LANE
    if len(prefixes) == 1:
        return next(iter(prefixes))
    if len(prefixes) > 1:
        return SERIAL_LANE
    return SERIAL_LANE


def _explicit_access_set(tx: dict[str, Any]) -> TxAccessSet | None:
    if "read_set" not in tx and "write_set" not in tx:
        return None

    raw_reads = tx.get("read_set", [])
    raw_writes = tx.get("write_set", [])
    raw_subject = tx.get("subject_set", [])
    raw_authority = tx.get("authority_set", [])

    if raw_reads is None:
        raw_reads = []
    if raw_writes is None:
        raw_writes = []
    if raw_subject is None:
        raw_subject = []
    if raw_authority is None:
        raw_authority = []

    valid_types = (list, tuple, set)
    if not isinstance(raw_reads, valid_types) or not isinstance(raw_writes, valid_types):
        return TxAccessSet(
            tx_id=str(tx.get("tx_id", "")),
            lane_hint=SERIAL_LANE,
            reads=(),
            writes=(),
            fail_closed_serial=True,
        )

    reads = _sorted_unique_strs(raw_reads)
    writes = _sorted_unique_strs(raw_writes)
    subject_keys = _sorted_unique_strs(raw_subject if isinstance(raw_subject, valid_types) else ())
    authority_keys = _sorted_unique_strs(raw_authority if isinstance(raw_authority, valid_types) else ())

    lane_hint = _infer_lane_from_keys(tuple(reads) + tuple(writes) + tuple(subject_keys) + tuple(authority_keys))
    fail_closed_serial = False
    scoped_keys = tuple(sorted(set(subject_keys) | set(authority_keys)))
    if scoped_keys and not set(scoped_keys).issubset(set(writes)):
        lane_hint = SERIAL_LANE
        fail_closed_serial = True

    return TxAccessSet(
        tx_id=str(tx.get("tx_id", "")),
        lane_hint=lane_hint,
        reads=reads,
        writes=writes,
        fail_closed_serial=fail_closed_serial,
        family=str(tx.get("family", TxFamily.UNKNOWN.value)),
        barrier_class=str(tx.get("barrier_class", BarrierClass.SCOPED_PARALLEL.value if lane_hint != SERIAL_LANE else BarrierClass.GLOBAL_BARRIER.value)),
        subject_keys=subject_keys,
        authority_keys=authority_keys,
        derived_only=bool(tx.get("derived_only", False)),
    )


def build_tx_access_set(tx: dict[str, Any]) -> TxAccessSet:
    explicit = _explicit_access_set(tx)
    if explicit is not None:
        return explicit

    descriptor = build_conflict_descriptor(tx)
    lane_hint = lane_hint_for_family(descriptor.family, descriptor.barrier_class)
    fail_closed_serial = False
    if descriptor.family == TxFamily.UNKNOWN:
        lane_hint = SERIAL_LANE
        fail_closed_serial = True
    elif descriptor.barrier_class == BarrierClass.GLOBAL_BARRIER:
        lane_hint = SERIAL_LANE
    elif descriptor.serial_only_on_missing_fields and not (descriptor.subject_keys or descriptor.write_keys or descriptor.authority_keys):
        lane_hint = SERIAL_LANE
        fail_closed_serial = True

    reads = _sorted_unique_strs(descriptor.read_keys)
    writes = _sorted_unique_strs(tuple(descriptor.write_keys) + tuple(descriptor.subject_keys) + tuple(descriptor.authority_keys))

    cross_domain_serial_types = {
        "GROUP_SIGNERS_SET",
        "GROUP_EMISSARY_ELECTION_FINALIZE",
        "ROLE_EMISSARY_SEAT",
        "ROLE_EMISSARY_REMOVE",
    }
    if descriptor.tx_type in cross_domain_serial_types:
        inferred_lane = _infer_lane_from_keys(tuple(reads) + tuple(writes))
        if inferred_lane == SERIAL_LANE:
            lane_hint = SERIAL_LANE

    return TxAccessSet(
        tx_id=descriptor.tx_id,
        lane_hint=lane_hint,
        reads=reads,
        writes=writes,
        fail_closed_serial=fail_closed_serial,
        family=descriptor.family.value,
        barrier_class=descriptor.barrier_class.value,
        subject_keys=descriptor.subject_keys,
        authority_keys=descriptor.authority_keys,
        derived_only=descriptor.derived_only,
    )


__all__ = [
    "CONTENT_LANE",
    "ECONOMICS_LANE",
    "GOVERNANCE_LANE",
    "IDENTITY_LANE",
    "SERIAL_LANE",
    "SOCIAL_LANE",
    "STORAGE_LANE",
    "TxAccessSet",
    "build_tx_access_set",
]
