from __future__ import annotations

import json
from pathlib import Path

from weall.runtime.read_write_sets import build_tx_access_set
from weall.runtime.tx_conflict_audit_samples import build_conflict_probe_tx
from weall.runtime.tx_conflicts import (
    BarrierClass,
    TxFamily,
    build_conflict_descriptor,
    lane_hint_for_family,
    lookup_rule,
)


def _tx_index_rows() -> list[dict[str, object]]:
    path = Path(__file__).resolve().parents[1] / "generated" / "tx_index.json"
    payload = json.loads(path.read_text(encoding="utf-8"))
    return list(payload["tx_types"])


def test_every_tx_type_in_canon_has_conflict_rule_and_non_unknown_family_batch6() -> None:
    rows = _tx_index_rows()
    missing: list[str] = []
    unknown: list[str] = []
    for row in rows:
        tx_type = str(row["name"])
        if lookup_rule(tx_type) is None:
            missing.append(tx_type)
        descriptor = build_conflict_descriptor(build_conflict_probe_tx(tx_type, seed="1"))
        if descriptor.family == TxFamily.UNKNOWN:
            unknown.append(tx_type)
    assert missing == []
    assert unknown == []


def test_every_probe_descriptor_has_materialized_conflict_keys_batch6() -> None:
    empty: list[str] = []
    duplicate_noise: list[str] = []
    for row in _tx_index_rows():
        tx_type = str(row["name"])
        descriptor = build_conflict_descriptor(build_conflict_probe_tx(tx_type, seed="2"))
        if not (descriptor.subject_keys or descriptor.write_keys or descriptor.authority_keys):
            empty.append(tx_type)
        merged = list(descriptor.subject_keys) + list(descriptor.read_keys) + list(descriptor.write_keys) + list(descriptor.authority_keys)
        if len(merged) != len(tuple(merged)):
            duplicate_noise.append(tx_type)
    assert empty == []
    assert duplicate_noise == []


def test_lane_hint_matches_family_contract_for_all_probe_txs_batch6() -> None:
    mismatches: list[tuple[str, str, str, str]] = []
    for row in _tx_index_rows():
        tx_type = str(row["name"])
        tx = build_conflict_probe_tx(tx_type, seed="3")
        descriptor = build_conflict_descriptor(tx)
        access = build_tx_access_set(tx)
        expected_lane = lane_hint_for_family(descriptor.family, descriptor.barrier_class)
        if access.lane_hint != expected_lane:
            mismatches.append((tx_type, descriptor.family.value, descriptor.barrier_class.value, access.lane_hint))
    assert mismatches == []


def test_global_barrier_probe_txs_are_always_serial_batch6() -> None:
    bad: list[str] = []
    for row in _tx_index_rows():
        tx_type = str(row["name"])
        tx = build_conflict_probe_tx(tx_type, seed="4")
        descriptor = build_conflict_descriptor(tx)
        access = build_tx_access_set(tx)
        if descriptor.barrier_class == BarrierClass.GLOBAL_BARRIER and access.lane_hint != "SERIAL":
            bad.append(tx_type)
    assert bad == []


def test_authority_barriers_materialize_authority_keys_batch6() -> None:
    missing: list[str] = []
    for row in _tx_index_rows():
        tx_type = str(row["name"])
        descriptor = build_conflict_descriptor(build_conflict_probe_tx(tx_type, seed="5"))
        if descriptor.barrier_class == BarrierClass.AUTHORITY_BARRIER and not descriptor.authority_keys:
            missing.append(tx_type)
    assert missing == []
