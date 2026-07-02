#!/usr/bin/env python3
from __future__ import annotations

"""Measure WeAll block-schedule survivability on real runtime paths.

This harness intentionally exercises ``WeAllExecutor.submit_tx`` -> persistent
mempool -> ``build_block_candidate`` -> ``commit_block_candidate`` -> follower
``apply_block``.  It does not change consensus semantics and it does not make
helper execution authoritative.  Helper timings are reported when the runtime
fast path is enabled; otherwise they are reported as zero/unmeasured.
"""

import argparse
import copy
import hashlib
import json
import os
import statistics
import sys
import tempfile
import time
from contextlib import contextmanager, nullcontext
from dataclasses import replace
from pathlib import Path
from typing import Any, Callable

REPO_ROOT = Path(__file__).resolve().parents[1]
SRC = REPO_ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

Json = dict[str, Any]


def _canon_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _fingerprint(value: Any) -> str:
    return hashlib.sha256(_canon_json(value).encode("utf-8")).hexdigest()

DEFAULT_TARGET_BLOCK_MS = 20_000
PROFILE_DEFAULTS: dict[str, dict[str, int]] = {
    "light": {"users": 10, "blocks": 4, "max_txs_per_block": 40, "txs_per_block_feed": 55},
    "active": {"users": 75, "blocks": 6, "max_txs_per_block": 160, "txs_per_block_feed": 220},
    "adversarial": {"users": 50, "blocks": 5, "max_txs_per_block": 120, "txs_per_block_feed": 180},
    "network": {"users": 25, "blocks": 5, "max_txs_per_block": 80, "txs_per_block_feed": 110},
}


def _now_ms() -> int:
    return int(time.time() * 1000)


def _ms(ns: int) -> float:
    return round(float(ns) / 1_000_000.0, 3)


PROFILE_TIMING_FIELDS = [
    "profile_total_wall_ms",
    "setup_wall_ms",
    "user_prepare_wall_ms",
    "tx_generation_wall_ms",
    "mempool_submit_wall_ms",
    "tx_submit_total_wall_ms",
    "tx_signature_verify_wall_ms",
    "tx_canonicalize_or_hash_wall_ms",
    "tx_nonce_check_wall_ms",
    "tx_mempool_insert_wall_ms",
    "tx_reject_wall_ms",
    "tx_duplicate_check_wall_ms",
    "block_loop_wall_ms",
    "follower_apply_wall_ms",
    "slow_observer_apply_wall_ms",
    "restart_replay_wall_ms",
    "evidence_write_wall_ms",
]

MEMPOOL_SUBMIT_TIMING_FIELDS = [
    "tx_submit_total_wall_ms",
    "tx_signature_verify_wall_ms",
    "tx_canonicalize_or_hash_wall_ms",
    "tx_nonce_check_wall_ms",
    "tx_mempool_insert_wall_ms",
    "tx_reject_wall_ms",
    "tx_duplicate_check_wall_ms",
]

TX_LOOP_MICROPHASE_FIELDS = [
    "leader_tx_decode_or_normalize_wall_ms",
    "leader_tx_id_or_hash_wall_ms",
    "leader_domain_dispatch_wall_ms",
    "leader_domain_apply_wall_ms",
    "leader_rollback_tracking_wall_ms",
    "follower_tx_decode_or_normalize_wall_ms",
    "follower_tx_id_or_hash_wall_ms",
    "follower_domain_dispatch_wall_ms",
    "follower_domain_apply_wall_ms",
    "follower_rollback_tracking_wall_ms",
    "slow_observer_tx_decode_or_normalize_wall_ms",
    "slow_observer_tx_id_or_hash_wall_ms",
    "slow_observer_domain_dispatch_wall_ms",
    "slow_observer_domain_apply_wall_ms",
    "slow_observer_rollback_tracking_wall_ms",
]

REPLAY_WRAPPER_PHASES = [
    "runtime_context_wall_ms",
    "block_hash_validation_wall_ms",
    "replay_admission_wall_ms",
    "state_deepcopy_wall_ms",
    "clock_policy_wall_ms",
    "pre_scheduler_wall_ms",
    "pre_system_emitter_wall_ms",
    "post_scheduler_wall_ms",
    "post_system_emitter_wall_ms",
    "system_queue_binding_wall_ms",
    "system_queue_prune_wall_ms",
    "receipts_root_wall_ms",
    "recent_anchor_wall_ms",
    "vrf_validation_wall_ms",
    "helper_validation_wall_ms",
    "metadata_update_wall_ms",
    "commit_persistence_wall_ms",
    "commit_block_json_wall_ms",
    "commit_state_json_wall_ms",
    "commit_prune_wall_ms",
    "replay_unattributed_wall_ms",
]

REPLAY_WRAPPER_TIMING_FIELDS = [
    f"{prefix}_{field}"
    for prefix in ("follower", "slow_observer")
    for field in REPLAY_WRAPPER_PHASES
]

ROLLBACK_JOURNAL_DIAGNOSTIC_FIELDS = [
    "rollback_snapshot_count",
    "rollback_snapshot_bytes_estimate",
    "rollback_snapshot_path_count",
    "rollback_snapshot_duplicate_path_count",
    "rollback_scalar_snapshot_count",
    "rollback_container_snapshot_count",
    "rollback_list_snapshot_count",
    "rollback_dict_snapshot_count",
]

ROLLBACK_JOURNAL_HOTPATH_FIELDS = [
    "rollback_top_snapshot_paths",
    "rollback_top_snapshot_prefixes",
    "rollback_top_snapshot_paths_by_estimated_bytes",
    "rollback_top_dict_snapshot_paths",
    "rollback_top_list_snapshot_paths",
    "rollback_top_duplicate_snapshot_paths",
    "rollback_snapshot_by_tx_kind",
]

BLOCK_TIMING_FIELDS = [
    "block_total_wall_ms",
    "candidate_selection_wall_ms",
    "leader_block_build_wall_ms",
    "leader_apply_or_execute_wall_ms",
    "follower_apply_wall_ms",
    "slow_observer_apply_wall_ms",
    "state_root_wall_ms",
    "receipt_or_summary_wall_ms",
    "leader_tx_loop_wall_ms",
    "follower_tx_loop_wall_ms",
    "slow_observer_tx_loop_wall_ms",
    "leader_receipt_build_wall_ms",
    "follower_receipt_build_wall_ms",
    "slow_observer_receipt_build_wall_ms",
    "leader_state_root_wall_ms",
    "follower_state_root_wall_ms",
    "slow_observer_state_root_wall_ms",
    "block_decode_or_materialize_wall_ms",
    "replay_admission_wall_ms",
    "rollback_journal_snapshot_wall_ms",
    *TX_LOOP_MICROPHASE_FIELDS,
    *REPLAY_WRAPPER_TIMING_FIELDS,
]


class PhaseProbe:
    def __init__(self) -> None:
        self.values: dict[str, int] = {}

    def add(self, key: str, ns: int) -> None:
        self.values[key] = int(self.values.get(key, 0)) + int(ns)

    def add_ms(self, key: str, ms: float) -> None:
        self.add(key, int(float(ms) * 1_000_000.0))

    @contextmanager
    def timed(self, key: str):
        start = time.perf_counter_ns()
        try:
            yield
        finally:
            self.add(key, time.perf_counter_ns() - start)

    def ms(self, key: str) -> float:
        return _ms(int(self.values.get(key, 0)))

    def reset(self) -> None:
        self.values.clear()


def _phase_value_ms(value: Any) -> float:
    try:
        out = float(value)
    except Exception:
        return 0.0
    if out < 0:
        return 0.0
    return round(out, 3)


def _top_bottleneck_phases(entries: list[tuple[str, Any]], *, limit: int = 5) -> Json:
    phases = [
        {"phase": str(name), "wall_ms": _phase_value_ms(value)}
        for name, value in entries
        if _phase_value_ms(value) >= 0.0
    ]
    phases.sort(key=lambda item: (-float(item["wall_ms"]), str(item["phase"])))
    return {"top_5": phases[: int(limit)]}


def _domain_dispatch_ms(probe: PhaseProbe, prefix: str) -> float:
    total = float(probe.ms(f"{prefix}_domain_dispatch_total_time_ns") or 0.0)
    apply = float(probe.ms(f"{prefix}_domain_apply_time_ns") or 0.0)
    return round(max(0.0, total - apply), 3)


def _tx_loop_microphase_values(probe: PhaseProbe, prefix: str) -> Json:
    return {
        f"{prefix}_tx_decode_or_normalize_wall_ms": probe.ms(f"{prefix}_tx_decode_or_normalize_time_ns"),
        f"{prefix}_tx_id_or_hash_wall_ms": probe.ms(f"{prefix}_tx_id_or_hash_time_ns"),
        f"{prefix}_domain_dispatch_wall_ms": _domain_dispatch_ms(probe, prefix),
        f"{prefix}_domain_apply_wall_ms": probe.ms(f"{prefix}_domain_apply_time_ns"),
        f"{prefix}_rollback_tracking_wall_ms": probe.ms(f"{prefix}_rollback_tracking_time_ns"),
    }


def _zero_tx_loop_microphase_values(prefix: str) -> Json:
    return {
        f"{prefix}_tx_decode_or_normalize_wall_ms": 0.0,
        f"{prefix}_tx_id_or_hash_wall_ms": 0.0,
        f"{prefix}_domain_dispatch_wall_ms": 0.0,
        f"{prefix}_domain_apply_wall_ms": 0.0,
        f"{prefix}_rollback_tracking_wall_ms": 0.0,
    }


def _replay_wrapper_phase_values(probe: PhaseProbe, *, role: str, apply_time_ms: float = 0.0) -> Json:
    prefix = str(role or "follower")
    raw = {
        "runtime_context_wall_ms": probe.ms(f"{prefix}_runtime_context_time_ns"),
        "block_hash_validation_wall_ms": probe.ms(f"{prefix}_block_hash_validation_time_ns"),
        "replay_admission_wall_ms": probe.ms(f"{prefix}_replay_admission_time_ns"),
        "state_deepcopy_wall_ms": probe.ms(f"{prefix}_state_deepcopy_time_ns"),
        "clock_policy_wall_ms": probe.ms(f"{prefix}_clock_policy_time_ns"),
        "pre_scheduler_wall_ms": probe.ms(f"{prefix}_pre_scheduler_time_ns"),
        "pre_system_emitter_wall_ms": probe.ms(f"{prefix}_pre_system_emitter_time_ns"),
        "post_scheduler_wall_ms": probe.ms(f"{prefix}_post_scheduler_time_ns"),
        "post_system_emitter_wall_ms": probe.ms(f"{prefix}_post_system_emitter_time_ns"),
        "system_queue_binding_wall_ms": probe.ms(f"{prefix}_system_queue_binding_time_ns"),
        "system_queue_prune_wall_ms": probe.ms(f"{prefix}_system_queue_prune_time_ns"),
        "receipts_root_wall_ms": probe.ms(f"{prefix}_receipt_build_time_ns"),
        "recent_anchor_wall_ms": probe.ms(f"{prefix}_recent_anchor_time_ns"),
        "vrf_validation_wall_ms": probe.ms(f"{prefix}_vrf_validation_time_ns"),
        "helper_validation_wall_ms": probe.ms(f"{prefix}_helper_validation_time_ns"),
        "metadata_update_wall_ms": probe.ms(f"{prefix}_metadata_update_time_ns"),
        "commit_persistence_wall_ms": probe.ms(f"{prefix}_commit_persistence_time_ns"),
        "commit_block_json_wall_ms": probe.ms(f"{prefix}_commit_block_json_time_ns"),
        "commit_state_json_wall_ms": probe.ms(f"{prefix}_commit_state_json_time_ns"),
        "commit_prune_wall_ms": probe.ms(f"{prefix}_commit_prune_time_ns"),
    }
    attributed = sum(
        float(raw.get(name) or 0.0)
        for name in [
            "runtime_context_wall_ms",
            "block_hash_validation_wall_ms",
            "replay_admission_wall_ms",
            "state_deepcopy_wall_ms",
            "clock_policy_wall_ms",
            "pre_scheduler_wall_ms",
            "pre_system_emitter_wall_ms",
            "post_scheduler_wall_ms",
            "post_system_emitter_wall_ms",
            "system_queue_binding_wall_ms",
            "system_queue_prune_wall_ms",
            "receipts_root_wall_ms",
            "recent_anchor_wall_ms",
            "vrf_validation_wall_ms",
            "helper_validation_wall_ms",
            "metadata_update_wall_ms",
            "commit_persistence_wall_ms",
            "block_decode_or_materialize_wall_ms",
            "tx_loop_wall_ms",
            "state_root_wall_ms",
        ]
    )
    # These four fields are already returned separately by _apply_to_follower but
    # are included in the unattributed calculation because they are non-overlap
    # replay phases.  Commit JSON/prune fields are subphases of commit_persistence
    # and are therefore intentionally excluded from the attributed sum.
    attributed += float(probe.ms("block_decode_or_materialize_time_ns") or 0.0)
    attributed += float(probe.ms(f"{prefix}_tx_loop_time_ns") or 0.0)
    attributed += float(probe.ms(f"{prefix}_state_root_time_ns") or 0.0)
    raw["replay_unattributed_wall_ms"] = round(max(0.0, float(apply_time_ms or 0.0) - attributed), 3)
    return raw


def _zero_replay_wrapper_phase_values(prefix: str) -> Json:
    return {f"{prefix}_{field}": 0.0 for field in REPLAY_WRAPPER_PHASES}


def _rollback_journal_diagnostic_values() -> Json:
    from weall.runtime.bounded_rollback import get_rollback_diagnostics

    raw = get_rollback_diagnostics()
    out: Json = {field: int(raw.get(field, 0) or 0) for field in ROLLBACK_JOURNAL_DIAGNOSTIC_FIELDS}
    for field in ROLLBACK_JOURNAL_HOTPATH_FIELDS:
        value = raw.get(field)
        if field == "rollback_snapshot_by_tx_kind":
            out[field] = dict(value or {})
        else:
            out[field] = list(value or [])
    return out


def _zero_rollback_journal_diagnostic_values() -> Json:
    out: Json = {field: 0 for field in ROLLBACK_JOURNAL_DIAGNOSTIC_FIELDS}
    for field in ROLLBACK_JOURNAL_HOTPATH_FIELDS:
        out[field] = {} if field == "rollback_snapshot_by_tx_kind" else []
    return out


def _merge_hotpath_items(existing: Any, incoming: Any, *, value_key: str = "count") -> list[Json]:
    merged: dict[str, int] = {}
    for items in (existing or [], incoming or []):
        if not isinstance(items, list):
            continue
        for item in items:
            if not isinstance(item, dict):
                continue
            path = str(item.get("path") or "")
            if not path:
                continue
            merged[path] = int(merged.get(path, 0)) + int(item.get(value_key, item.get("count", 0)) or 0)
    sorted_items = sorted(merged.items(), key=lambda item: (-int(item[1]), str(item[0])))
    return [{"path": path, value_key: int(value)} for path, value in sorted_items[:12]]


def _merge_kind_counts(existing: Any, incoming: Any) -> Json:
    merged: dict[str, int] = {}
    for src in (existing or {}, incoming or {}):
        if not isinstance(src, dict):
            continue
        for key, value in src.items():
            merged[str(key)] = int(merged.get(str(key), 0)) + int(value or 0)
    return dict(sorted(merged.items(), key=lambda item: (-int(item[1]), str(item[0]))))


def _add_rollback_journal_diagnostics(target: Json, source: Json) -> None:
    for field in ROLLBACK_JOURNAL_DIAGNOSTIC_FIELDS:
        target[field] = int(target.get(field, 0) or 0) + int(source.get(field, 0) or 0)
    for field in ROLLBACK_JOURNAL_HOTPATH_FIELDS:
        if field == "rollback_snapshot_by_tx_kind":
            target[field] = _merge_kind_counts(target.get(field), source.get(field))
        else:
            value_key = "bytes_estimate" if field == "rollback_top_snapshot_paths_by_estimated_bytes" else "count"
            target[field] = _merge_hotpath_items(target.get(field), source.get(field), value_key=value_key)


def _profile_bottleneck_summary(profile: Json) -> Json:
    entries: list[tuple[str, Any]] = []
    for field in PROFILE_TIMING_FIELDS:
        entries.append((field, profile.get(field, 0.0)))
    for idx, block in enumerate(profile.get("block_measurements") or []):
        if not isinstance(block, dict):
            continue
        for field in BLOCK_TIMING_FIELDS:
            entries.append((f"block[{idx}].{field}", block.get(field, 0.0)))
    return _top_bottleneck_phases(entries)


def _artifact_bottleneck_summary(profiles: list[Json], *, evidence_write_wall_ms: float = 0.0) -> Json:
    entries: list[tuple[str, Any]] = [("evidence_write_wall_ms", evidence_write_wall_ms)]
    for profile in profiles:
        label = f"{profile.get('profile')}:{profile.get('execution_model')}"
        for field in PROFILE_TIMING_FIELDS:
            entries.append((f"{label}.{field}", profile.get(field, 0.0)))
        for idx, block in enumerate(profile.get("block_measurements") or []):
            if not isinstance(block, dict):
                continue
            for field in BLOCK_TIMING_FIELDS:
                entries.append((f"{label}.block[{idx}].{field}", block.get(field, 0.0)))
    return _top_bottleneck_phases(entries)


@contextmanager
def _patched_domain_apply_microphase_timing(probe: PhaseProbe, *, role: str):
    """Measure tx-loop microphases inside domain apply without changing semantics.

    The harness patches module-level dependency seams only while producing or
    replaying one block.  It does not alter production routing or consensus
    behavior; it records where the already-authoritative serial tx loop spends
    time.
    """

    import weall.runtime.bounded_rollback as bounded_rollback
    import weall.runtime.domain_apply as domain_apply
    import weall.runtime.domain_dispatch as domain_dispatch

    prefix = str(role or "leader")
    old_apply_internal = domain_apply._apply_tx_internal
    old_tx_envelope = domain_apply.TxEnvelope
    old_resolve_applier = domain_dispatch.resolve_applier_for_tx_type
    old_record_dict_key = bounded_rollback.RollbackJournal.record_dict_key
    old_record_list_state = bounded_rollback.RollbackJournal.record_list_state
    old_record_list_append = bounded_rollback.RollbackJournal.record_list_append
    old_set_tx_kind = getattr(bounded_rollback, "set_rollback_diagnostic_tx_kind", None)
    old_reset_tx_kind = getattr(bounded_rollback, "reset_rollback_diagnostic_tx_kind", None)

    class TimedTxEnvelope:
        @staticmethod
        def from_json(*args: Any, **kwargs: Any) -> Any:
            with probe.timed(f"{prefix}_tx_decode_or_normalize_time_ns"):
                return old_tx_envelope.from_json(*args, **kwargs)

    def timed_resolve_applier(tx_type: str) -> Any:
        routed = old_resolve_applier(tx_type)
        if routed is None:
            return None

        def timed_routed(state: Json, env: Any) -> Any:
            with probe.timed(f"{prefix}_domain_apply_time_ns"):
                return routed(state, env)

        try:
            timed_routed.__name__ = getattr(routed, "__name__", "timed_routed")
        except Exception:
            pass
        return timed_routed

    def timed_apply_internal(*args: Any, **kwargs: Any) -> Any:
        # Time the full dispatch path.  The actual domain handler is timed
        # separately by timed_resolve_applier; evidence reports dispatch as
        # full-dispatch-minus-handler to avoid double-counting domain apply.
        env = args[1] if len(args) > 1 else kwargs.get("env")
        tx_kind = str(getattr(env, "tx_type", "") or (env.get("tx_type") if isinstance(env, dict) else "") or "UNKNOWN")
        token = old_set_tx_kind(tx_kind) if callable(old_set_tx_kind) else None
        try:
            with probe.timed(f"{prefix}_domain_dispatch_total_time_ns"):
                return old_apply_internal(*args, **kwargs)
        finally:
            if token is not None and callable(old_reset_tx_kind):
                old_reset_tx_kind(token)

    def timed_record_dict_key(self: Any, *args: Any, **kwargs: Any) -> Any:
        with probe.timed(f"{prefix}_rollback_tracking_time_ns"):
            with probe.timed("rollback_journal_snapshot_time_ns"):
                return old_record_dict_key(self, *args, **kwargs)

    def timed_record_list_state(self: Any, *args: Any, **kwargs: Any) -> Any:
        with probe.timed(f"{prefix}_rollback_tracking_time_ns"):
            with probe.timed("rollback_journal_snapshot_time_ns"):
                return old_record_list_state(self, *args, **kwargs)

    def timed_record_list_append(self: Any, *args: Any, **kwargs: Any) -> Any:
        with probe.timed(f"{prefix}_rollback_tracking_time_ns"):
            with probe.timed("rollback_journal_snapshot_time_ns"):
                return old_record_list_append(self, *args, **kwargs)

    domain_apply.TxEnvelope = TimedTxEnvelope
    domain_apply._apply_tx_internal = timed_apply_internal
    domain_dispatch.resolve_applier_for_tx_type = timed_resolve_applier
    bounded_rollback.RollbackJournal.record_dict_key = timed_record_dict_key
    bounded_rollback.RollbackJournal.record_list_state = timed_record_list_state
    bounded_rollback.RollbackJournal.record_list_append = timed_record_list_append
    try:
        yield
    finally:
        domain_apply.TxEnvelope = old_tx_envelope
        domain_apply._apply_tx_internal = old_apply_internal
        domain_dispatch.resolve_applier_for_tx_type = old_resolve_applier
        bounded_rollback.RollbackJournal.record_dict_key = old_record_dict_key
        bounded_rollback.RollbackJournal.record_list_state = old_record_list_state
        bounded_rollback.RollbackJournal.record_list_append = old_record_list_append


@contextmanager
def _patched_block_builder_timing(executor: Any, probe: PhaseProbe, *, execution_model: str = "deepcopy"):
    """Patch dependency-injection seams to time the exact leader code path.

    The runtime already routes extracted block-builder dependencies through
    ``RuntimeContext.from_executor``.  This context manager wraps those callables
    for measurement only and restores them immediately after one block attempt.
    """

    import weall.runtime.block_builder as block_builder
    import weall.runtime.runtime_context as runtime_context

    old_compute_state_root = block_builder.compute_state_root
    old_admit_block_txs = block_builder.admit_block_txs
    old_compute_receipts_root = block_builder.compute_receipts_root
    old_compute_tx_id = block_builder.compute_tx_id
    old_tx_envelope = block_builder.TxEnvelope
    old_runtime_context_from_executor = block_builder.RuntimeContext.from_executor
    old_runtime_context_module_from_executor = runtime_context.RuntimeContext.from_executor
    old_helper_meta = getattr(executor, "_build_helper_execution_metadata", None)

    def timed_compute_state_root(*args: Any, **kwargs: Any) -> Any:
        with probe.timed("state_root_time_ns"):
            with probe.timed("leader_state_root_time_ns"):
                return old_compute_state_root(*args, **kwargs)

    def timed_admit_block_txs(*args: Any, **kwargs: Any) -> Any:
        with probe.timed("block_admission_time_ns"):
            return old_admit_block_txs(*args, **kwargs)

    def timed_compute_receipts_root(*args: Any, **kwargs: Any) -> Any:
        with probe.timed("leader_receipt_build_time_ns"):
            return old_compute_receipts_root(*args, **kwargs)

    def timed_compute_tx_id(*args: Any, **kwargs: Any) -> Any:
        with probe.timed("leader_tx_id_or_hash_time_ns"):
            return old_compute_tx_id(*args, **kwargs)

    class TimedTxEnvelope:
        @staticmethod
        def from_json(*args: Any, **kwargs: Any) -> Any:
            with probe.timed("block_decode_or_materialize_time_ns"):
                with probe.timed("leader_tx_decode_or_normalize_time_ns"):
                    return old_tx_envelope.from_json(*args, **kwargs)

    def timed_from_executor(ex: Any) -> Any:
        ctx = old_runtime_context_from_executor(ex)
        from weall.runtime.domain_apply import (
            apply_tx_atomic_meta_bounded_rollback,
            apply_tx_atomic_meta_deepcopy,
        )

        if str(execution_model) == "deepcopy":
            selected_apply = apply_tx_atomic_meta_deepcopy
        elif str(execution_model) == "bounded_rollback":
            selected_apply = apply_tx_atomic_meta_bounded_rollback
        else:
            selected_apply = ctx.tx_execution_set.apply_tx_atomic_meta

        def timed_apply(*args: Any, **kwargs: Any) -> Any:
            with probe.timed("execution_time_ns"):
                with probe.timed("leader_tx_loop_time_ns"):
                    return selected_apply(*args, **kwargs)

        tx_set = replace(ctx.tx_execution_set, apply_tx_atomic_meta=timed_apply)
        return replace(ctx, tx_execution_set=tx_set)

    def timed_helper_meta(*args: Any, **kwargs: Any) -> Any:
        if old_helper_meta is None:
            return {}
        with probe.timed("helper_planning_time_ns"):
            return old_helper_meta(*args, **kwargs)

    block_builder.compute_state_root = timed_compute_state_root
    block_builder.admit_block_txs = timed_admit_block_txs
    block_builder.compute_receipts_root = timed_compute_receipts_root
    block_builder.compute_tx_id = timed_compute_tx_id
    block_builder.TxEnvelope = TimedTxEnvelope
    block_builder.RuntimeContext.from_executor = staticmethod(timed_from_executor)
    # Keep runtime_context patched too for extracted callers that import it directly.
    runtime_context.RuntimeContext.from_executor = staticmethod(timed_from_executor)
    if old_helper_meta is not None:
        setattr(executor, "_build_helper_execution_metadata", timed_helper_meta)
    domain_microphase_cm = _patched_domain_apply_microphase_timing(probe, role="leader")
    domain_microphase_cm.__enter__()
    try:
        yield
    finally:
        domain_microphase_cm.__exit__(None, None, None)
        block_builder.compute_state_root = old_compute_state_root
        block_builder.admit_block_txs = old_admit_block_txs
        block_builder.compute_receipts_root = old_compute_receipts_root
        block_builder.compute_tx_id = old_compute_tx_id
        block_builder.TxEnvelope = old_tx_envelope
        block_builder.RuntimeContext.from_executor = old_runtime_context_from_executor
        runtime_context.RuntimeContext.from_executor = old_runtime_context_module_from_executor
        if old_helper_meta is not None:
            setattr(executor, "_build_helper_execution_metadata", old_helper_meta)


@contextmanager
def _patched_block_replay_timing(follower: Any, probe: PhaseProbe, *, role: str) -> Any:
    """Measure follower/observer replay subphases without changing replay semantics."""

    import weall.runtime.block_commit as block_commit
    import weall.runtime.block_replay as block_replay
    import weall.runtime.runtime_context as runtime_context

    prefix = str(role or "follower")
    old_compute_state_root = block_replay.compute_state_root
    old_admit_block_txs = block_replay.admit_block_txs
    old_compute_receipts_root = block_replay.compute_receipts_root
    old_tx_envelope = block_replay.TxEnvelope
    old_runtime_context_from_executor = block_replay.RuntimeContext.from_executor
    old_runtime_context_module_from_executor = runtime_context.RuntimeContext.from_executor
    old_ensure_block_hash = block_replay.ensure_block_hash
    old_deepcopy = block_replay.copy.deepcopy
    old_runtime_block_clock_policy = block_replay.runtime_block_clock_policy
    old_run_replay_pre_schedulers = block_replay.run_replay_pre_schedulers
    old_run_replay_post_schedulers = block_replay.run_replay_post_schedulers
    old_emit_system_txs = block_replay.emit_system_txs
    old_queue_item_phase = block_replay.queue_item_phase
    old_prune_emitted = block_replay.prune_emitted
    old_validate_system_tx_queue_binding = block_replay.validate_system_tx_queue_binding
    old_compute_recent_block_anchor = block_replay.compute_recent_block_anchor
    old_recent_block_ids_from_state = block_replay.recent_block_ids_from_state
    old_recent_block_anchor_required_for_height = block_replay.recent_block_anchor_required_for_height
    old_compute_helper_execution_root = block_replay.compute_helper_execution_root
    old_verify_vrf_record = block_replay.verify_vrf_record
    old_compute_block_hash = block_replay.compute_block_hash
    old_compute_block_id = block_replay.compute_block_id
    old_commit_block_candidate = getattr(follower, "commit_block_candidate", None)

    def timed_compute_state_root(*args: Any, **kwargs: Any) -> Any:
        with probe.timed(f"{prefix}_state_root_time_ns"):
            return old_compute_state_root(*args, **kwargs)

    def timed_admit_block_txs(*args: Any, **kwargs: Any) -> Any:
        with probe.timed("replay_admission_time_ns"):
            with probe.timed(f"{prefix}_replay_admission_time_ns"):
                return old_admit_block_txs(*args, **kwargs)

    def timed_compute_receipts_root(*args: Any, **kwargs: Any) -> Any:
        with probe.timed(f"{prefix}_receipt_build_time_ns"):
            return old_compute_receipts_root(*args, **kwargs)

    class TimedTxEnvelope:
        @staticmethod
        def from_json(*args: Any, **kwargs: Any) -> Any:
            with probe.timed("block_decode_or_materialize_time_ns"):
                with probe.timed(f"{prefix}_tx_decode_or_normalize_time_ns"):
                    return old_tx_envelope.from_json(*args, **kwargs)

    def timed_from_executor(ex: Any) -> Any:
        with probe.timed(f"{prefix}_runtime_context_time_ns"):
            ctx = old_runtime_context_from_executor(ex)
        original_apply = ctx.tx_execution_set.apply_tx_atomic_meta

        def timed_apply(*args: Any, **kwargs: Any) -> Any:
            with probe.timed(f"{prefix}_tx_loop_time_ns"):
                return original_apply(*args, **kwargs)

        return replace(ctx, tx_execution_set=replace(ctx.tx_execution_set, apply_tx_atomic_meta=timed_apply))

    def timed_ensure_block_hash(*args: Any, **kwargs: Any) -> Any:
        with probe.timed(f"{prefix}_block_hash_validation_time_ns"):
            return old_ensure_block_hash(*args, **kwargs)

    def timed_deepcopy(*args: Any, **kwargs: Any) -> Any:
        with probe.timed(f"{prefix}_state_deepcopy_time_ns"):
            return old_deepcopy(*args, **kwargs)

    def timed_runtime_block_clock_policy(*args: Any, **kwargs: Any) -> Any:
        with probe.timed(f"{prefix}_clock_policy_time_ns"):
            return old_runtime_block_clock_policy(*args, **kwargs)

    def timed_run_replay_pre_schedulers(*args: Any, **kwargs: Any) -> Any:
        with probe.timed(f"{prefix}_pre_scheduler_time_ns"):
            return old_run_replay_pre_schedulers(*args, **kwargs)

    def timed_run_replay_post_schedulers(*args: Any, **kwargs: Any) -> Any:
        with probe.timed(f"{prefix}_post_scheduler_time_ns"):
            return old_run_replay_post_schedulers(*args, **kwargs)

    def timed_emit_system_txs(*args: Any, **kwargs: Any) -> Any:
        phase = ""
        if len(args) >= 4:
            phase = str(args[3] or "")
        phase = str(kwargs.get("phase") or phase or "")
        field = f"{prefix}_post_system_emitter_time_ns" if phase == "post" else f"{prefix}_pre_system_emitter_time_ns"
        with probe.timed(field):
            return old_emit_system_txs(*args, **kwargs)

    def timed_queue_item_phase(*args: Any, **kwargs: Any) -> Any:
        with probe.timed(f"{prefix}_system_queue_binding_time_ns"):
            return old_queue_item_phase(*args, **kwargs)

    def timed_validate_system_tx_queue_binding(*args: Any, **kwargs: Any) -> Any:
        with probe.timed(f"{prefix}_system_queue_binding_time_ns"):
            return old_validate_system_tx_queue_binding(*args, **kwargs)

    def timed_prune_emitted(*args: Any, **kwargs: Any) -> Any:
        with probe.timed(f"{prefix}_system_queue_prune_time_ns"):
            return old_prune_emitted(*args, **kwargs)

    def timed_recent_block_anchor_required_for_height(*args: Any, **kwargs: Any) -> Any:
        with probe.timed(f"{prefix}_recent_anchor_time_ns"):
            return old_recent_block_anchor_required_for_height(*args, **kwargs)

    def timed_recent_block_ids_from_state(*args: Any, **kwargs: Any) -> Any:
        with probe.timed(f"{prefix}_recent_anchor_time_ns"):
            return old_recent_block_ids_from_state(*args, **kwargs)

    def timed_compute_recent_block_anchor(*args: Any, **kwargs: Any) -> Any:
        with probe.timed(f"{prefix}_recent_anchor_time_ns"):
            return old_compute_recent_block_anchor(*args, **kwargs)

    def timed_compute_helper_execution_root(*args: Any, **kwargs: Any) -> Any:
        with probe.timed(f"{prefix}_helper_validation_time_ns"):
            return old_compute_helper_execution_root(*args, **kwargs)

    def timed_verify_vrf_record(*args: Any, **kwargs: Any) -> Any:
        with probe.timed(f"{prefix}_vrf_validation_time_ns"):
            return old_verify_vrf_record(*args, **kwargs)

    def timed_compute_block_hash(*args: Any, **kwargs: Any) -> Any:
        with probe.timed(f"{prefix}_block_hash_validation_time_ns"):
            return old_compute_block_hash(*args, **kwargs)

    def timed_compute_block_id(*args: Any, **kwargs: Any) -> Any:
        with probe.timed(f"{prefix}_metadata_update_time_ns"):
            return old_compute_block_id(*args, **kwargs)

    def _commit_json_field(value: Any) -> str:
        if isinstance(value, dict) and ("txs" in value or "header" in value or "block_id" in value):
            return f"{prefix}_commit_block_json_time_ns"
        if isinstance(value, dict) and ("accounts" in value or "height" in value or "tip" in value):
            return f"{prefix}_commit_state_json_time_ns"
        return f"{prefix}_metadata_update_time_ns"

    def timed_commit_block_candidate(*args: Any, **kwargs: Any) -> Any:
        old_commit_canon_json = block_commit._canon_json
        old_commit_prune = block_commit.prune_emitted_system_queue

        def timed_commit_canon_json(value: Any) -> str:
            with probe.timed(_commit_json_field(value)):
                return old_commit_canon_json(value)

        def timed_commit_prune(*cargs: Any, **ckwargs: Any) -> Any:
            with probe.timed(f"{prefix}_commit_prune_time_ns"):
                return old_commit_prune(*cargs, **ckwargs)

        block_commit._canon_json = timed_commit_canon_json
        block_commit.prune_emitted_system_queue = timed_commit_prune
        try:
            with probe.timed(f"{prefix}_commit_persistence_time_ns"):
                return old_commit_block_candidate(*args, **kwargs)
        finally:
            block_commit._canon_json = old_commit_canon_json
            block_commit.prune_emitted_system_queue = old_commit_prune

    block_replay.compute_state_root = timed_compute_state_root
    block_replay.admit_block_txs = timed_admit_block_txs
    block_replay.compute_receipts_root = timed_compute_receipts_root
    block_replay.TxEnvelope = TimedTxEnvelope
    block_replay.RuntimeContext.from_executor = staticmethod(timed_from_executor)
    runtime_context.RuntimeContext.from_executor = staticmethod(timed_from_executor)
    block_replay.ensure_block_hash = timed_ensure_block_hash
    block_replay.copy.deepcopy = timed_deepcopy
    block_replay.runtime_block_clock_policy = timed_runtime_block_clock_policy
    block_replay.run_replay_pre_schedulers = timed_run_replay_pre_schedulers
    block_replay.run_replay_post_schedulers = timed_run_replay_post_schedulers
    block_replay.emit_system_txs = timed_emit_system_txs
    block_replay.queue_item_phase = timed_queue_item_phase
    block_replay.prune_emitted = timed_prune_emitted
    block_replay.validate_system_tx_queue_binding = timed_validate_system_tx_queue_binding
    block_replay.compute_recent_block_anchor = timed_compute_recent_block_anchor
    block_replay.recent_block_ids_from_state = timed_recent_block_ids_from_state
    block_replay.recent_block_anchor_required_for_height = timed_recent_block_anchor_required_for_height
    block_replay.compute_helper_execution_root = timed_compute_helper_execution_root
    block_replay.verify_vrf_record = timed_verify_vrf_record
    block_replay.compute_block_hash = timed_compute_block_hash
    block_replay.compute_block_id = timed_compute_block_id
    if callable(old_commit_block_candidate):
        setattr(follower, "commit_block_candidate", timed_commit_block_candidate)
    domain_microphase_cm = _patched_domain_apply_microphase_timing(probe, role=prefix)
    domain_microphase_cm.__enter__()
    try:
        yield
    finally:
        domain_microphase_cm.__exit__(None, None, None)
        block_replay.compute_state_root = old_compute_state_root
        block_replay.admit_block_txs = old_admit_block_txs
        block_replay.compute_receipts_root = old_compute_receipts_root
        block_replay.TxEnvelope = old_tx_envelope
        block_replay.RuntimeContext.from_executor = old_runtime_context_from_executor
        runtime_context.RuntimeContext.from_executor = old_runtime_context_module_from_executor
        block_replay.ensure_block_hash = old_ensure_block_hash
        block_replay.copy.deepcopy = old_deepcopy
        block_replay.runtime_block_clock_policy = old_runtime_block_clock_policy
        block_replay.run_replay_pre_schedulers = old_run_replay_pre_schedulers
        block_replay.run_replay_post_schedulers = old_run_replay_post_schedulers
        block_replay.emit_system_txs = old_emit_system_txs
        block_replay.queue_item_phase = old_queue_item_phase
        block_replay.prune_emitted = old_prune_emitted
        block_replay.validate_system_tx_queue_binding = old_validate_system_tx_queue_binding
        block_replay.compute_recent_block_anchor = old_compute_recent_block_anchor
        block_replay.recent_block_ids_from_state = old_recent_block_ids_from_state
        block_replay.recent_block_anchor_required_for_height = old_recent_block_anchor_required_for_height
        block_replay.compute_helper_execution_root = old_compute_helper_execution_root
        block_replay.verify_vrf_record = old_verify_vrf_record
        block_replay.compute_block_hash = old_compute_block_hash
        block_replay.compute_block_id = old_compute_block_id
        if callable(old_commit_block_candidate):
            setattr(follower, "commit_block_candidate", old_commit_block_candidate)


def _make_executor(db_path: str, *, node_id: str, chain_id: str, helper_fast_path: bool = False) -> Any:
    from weall.runtime.executor import WeAllExecutor

    os.environ.setdefault("WEALL_MODE", "dev")
    os.environ.setdefault("WEALL_UNSAFE_DEV", "1")
    os.environ.setdefault("WEALL_SQLITE_ALLOW_NON_WAL", "1")
    os.environ.setdefault("WEALL_MEMPOOL_SELECTION_POLICY", "canonical")
    os.environ.setdefault("WEALL_DISABLE_BLOCK_PRODUCER", "1")
    os.environ.setdefault("WEALL_BLOCK_INTERVAL_MS", str(DEFAULT_TARGET_BLOCK_MS))
    os.environ.setdefault("WEALL_PRODUCER_INTERVAL_MS", str(DEFAULT_TARGET_BLOCK_MS))
    if helper_fast_path:
        os.environ.setdefault("WEALL_HELPER_EXECUTION_FAST_PATH", "1")
    else:
        os.environ.setdefault("WEALL_HELPER_EXECUTION_FAST_PATH", "0")

    return WeAllExecutor(
        db_path=db_path,
        node_id=node_id,
        chain_id=chain_id,
        tx_index_path=str(REPO_ROOT / "generated" / "tx_index.json"),
    )


def _account(account_id: str, nonce: int = 1) -> Json:
    return {
        "banned": False,
        "devices": {"by_id": {}},
        "keys": {"by_id": {}},
        "locked": False,
        "nonce": int(nonce),
        "poh_tier": 2,
        "recovery": {"config": None, "proposals": {}},
        "reputation": 10,
        "reputation_milli": 10_000,
        "session_keys": {},
    }


def _seed_state(executor: Any, users: list[str]) -> Json:
    st = executor.read_state()
    st["chain_id"] = str(getattr(executor, "chain_id", "block-schedule-survivability"))
    st["height"] = int(st.get("height") or 0)
    accounts = dict(st.get("accounts") or {})
    for user in users:
        accounts[user] = _account(user, nonce=1)
    accounts.setdefault("SYSTEM", {"nonce": 0, "poh_tier": 0, "banned": False, "locked": False})
    st["accounts"] = accounts
    content = dict(st.get("content") or {})
    content.setdefault("posts", {})["seed-post"] = {
        "id": "seed-post",
        "post_id": "seed-post",
        "author": users[0],
        "body": "seed post for load rehearsal",
        "visibility": "public",
        "deleted": False,
        "locked": False,
        "labels": [],
    }
    content.setdefault("comments", {})
    content.setdefault("media", {})
    content.setdefault("reactions", {})
    content.setdefault("flags", {})
    st["content"] = content
    st.setdefault("groups_by_id", {})["seed-group"] = {
        "group_id": "seed-group",
        "created_by": users[0],
        "charter": "Seed public group for block cadence load.",
        "meta": {"visibility": "public", "read_visibility": "public", "public_only": True},
        "members": {users[0]: {"account": users[0], "role": "creator"}},
        "permissions": {"read": "public", "post": "members", "comment": "members", "vote": "members"},
        "signers": [users[0]],
        "threshold": 1,
        "moderators": [],
        "emissaries": [],
        "public_only": True,
        "read_visibility": "public",
        "visibility": "public",
    }
    st.setdefault("proposals", {})["seed-prop"] = {
        "proposal_id": "seed-prop",
        "creator": users[0],
        "title": "Seed poll",
        "body": "Seed poll for block cadence load.",
        "stage": "poll",
        "rules": {"start_stage": "poll", "auto_progress_enabled": False},
        "actions": [],
        "poll_votes": {},
        "votes": {},
        "eligible_validator_ids": [],
        "eligible_validator_count": 0,
        "required_votes": 0,
        "electorate_source": "",
        "comments": [],
        "versions": [],
        "current_version": 1,
        "updated_at_height": int(st.get("height") or 0),
    }
    # Dispute vote validity is expensive and requires explicit juror assignment;
    # seed a standing dispute so adversarial valid load can include juror actions.
    st.setdefault("disputes_by_id", {})["seed-dispute"] = {
        "dispute_id": "seed-dispute",
        "target_type": "content",
        "target_id": "seed-post",
        "opened_by": users[0],
        "reason": "seed",
        "stage": "review",
        "resolved": False,
        "jurors": {users[1] if len(users) > 1 else users[0]: {"status": "accepted", "accepted_at_height": 0}},
        "votes": {},
        "created_at_height": 0,
        "deadline_height": 10_000_000,
    }
    roles = dict(st.get("roles") or {})
    roles.setdefault("validators", {"active_set": users[: min(4, len(users))]})
    roles.setdefault("jurors", {"active_set": users[: min(12, len(users))]})
    st["roles"] = roles
    executor._ledger_store.write_state_snapshot(st)  # type: ignore[attr-defined]
    try:
        executor.state = copy.deepcopy(st)
    except Exception:
        pass
    return st


def _clone_seed_to_follower(follower: Any, state: Json) -> None:
    follower._ledger_store.write_state_snapshot(copy.deepcopy(state))  # type: ignore[attr-defined]
    try:
        follower.state = copy.deepcopy(state)
    except Exception:
        pass


def _tx(tx_type: str, signer: str, nonce: int, payload: Json) -> Json:
    return {"tx_type": tx_type, "signer": signer, "nonce": int(nonce), "payload": payload}


def _next_nonce(next_nonces: dict[str, int], signer: str) -> int:
    nonce = int(next_nonces.get(signer, 2))
    next_nonces[signer] = nonce + 1
    return nonce


def _valid_payload_for(kind: str, signer: str, nonce: int, i: int, users: list[str], profile: str) -> Json:
    target = users[(users.index(signer) + 1) % len(users)] if signer in users and len(users) > 1 else users[0]
    if kind == "PROFILE_UPDATE":
        return {"display_name": f"User {signer} {i}", "bio": f"block cadence profile update {i}"}
    if kind == "CONTENT_POST_CREATE":
        return {"post_id": f"post:{signer}:{nonce}", "body": f"public load post {i} by {signer}", "visibility": "public", "tags": ["load", profile], "media": []}
    if kind == "CONTENT_COMMENT_CREATE":
        return {"comment_id": f"comment:{signer}:{nonce}", "post_id": "seed-post", "body": f"public load comment {i}"}
    if kind == "CONTENT_REACTION_SET":
        return {"target_id": "seed-post", "reaction": "like" if i % 2 == 0 else "support"}
    if kind == "FOLLOW_SET":
        return {"target": target, "active": True}
    if kind == "GROUP_CREATE":
        return {"group_id": f"g:{signer.strip('@').replace(':', '-')}-{nonce}", "charter": f"Public load group {i}"}
    if kind == "GROUP_MEMBERSHIP_REQUEST":
        return {"group_id": "seed-group"}
    if kind == "GOV_PROPOSAL_CREATE":
        return {"proposal_id": f"prop:{signer.strip('@')}:{nonce}", "title": f"Load proposal {i}", "body": "Measured public governance load.", "rules": {"start_stage": "poll", "auto_progress_enabled": False}, "actions": []}
    if kind == "GOV_PROPOSAL_COMMENT":
        return {"proposal_id": "seed-prop", "body": f"governance comment {i}"}
    if kind == "GOV_VOTE_CAST":
        return {"proposal_id": "seed-prop", "vote": "yes" if i % 3 else "abstain"}
    if kind == "DISPUTE_OPEN":
        return {"dispute_id": f"dispute:{signer.strip('@')}:{nonce}", "target_type": "content", "target_id": "seed-post", "reason": f"valid stress dispute {i}"}
    if kind == "CONTENT_FLAG":
        return {"flag_id": f"flag:{signer.strip('@')}:{nonce}", "target_id": "seed-post", "reason": "stress flag"}
    return {"note": f"unsupported generator kind {kind}"}


def _profile_mix(profile: str) -> list[str]:
    if profile == "light":
        return [
            "PROFILE_UPDATE",
            "CONTENT_POST_CREATE",
            "CONTENT_COMMENT_CREATE",
            "CONTENT_REACTION_SET",
            "FOLLOW_SET",
        ]
    if profile == "active":
        return [
            "CONTENT_POST_CREATE",
            "CONTENT_COMMENT_CREATE",
            "CONTENT_REACTION_SET",
            "FOLLOW_SET",
            "GROUP_CREATE",
            "GROUP_MEMBERSHIP_REQUEST",
            "GOV_PROPOSAL_CREATE",
            "GOV_PROPOSAL_COMMENT",
            "GOV_VOTE_CAST",
            "CONTENT_FLAG",
        ]
    if profile == "adversarial":
        return [
            "DISPUTE_OPEN",
            "CONTENT_FLAG",
            "GOV_PROPOSAL_CREATE",
            "GROUP_CREATE",
            "CONTENT_COMMENT_CREATE",
            "CONTENT_REACTION_SET",
            "GOV_VOTE_CAST",
            "GROUP_MEMBERSHIP_REQUEST",
        ]
    return [
        "CONTENT_POST_CREATE",
        "CONTENT_COMMENT_CREATE",
        "CONTENT_REACTION_SET",
        "GROUP_MEMBERSHIP_REQUEST",
        "GOV_VOTE_CAST",
    ]


def _submit_profile_load(
    executor: Any,
    *,
    profile: str,
    users: list[str],
    next_nonces: dict[str, int],
    count: int,
    phase_probe: PhaseProbe | None = None,
) -> Json:
    mix = _profile_mix(profile)
    admitted = 0
    rejected = 0
    rejected_by_code: dict[str, int] = {}
    submitted_by_type: dict[str, int] = {}
    accepted_by_type: dict[str, int] = {}
    malformed_submitted = 0
    malformed_rejected = 0
    txs: list[Json] = []
    tx_kinds: list[str] = []
    malformed_flags: list[bool] = []

    with (phase_probe.timed("tx_generation_wall_ns") if phase_probe is not None else nullcontext()):
        for i in range(int(count)):
            if profile == "adversarial" and i % 17 == 0:
                malformed_submitted += 1
                bad = {"tx_type": "CONTENT_POST_CREATE", "signer": "", "nonce": -1, "payload": {"body": "bad"}}
                txs.append(bad)
                tx_kinds.append("CONTENT_POST_CREATE")
                malformed_flags.append(True)
                continue
            signer = users[i % len(users)]
            kind = mix[i % len(mix)]
            nonce = _next_nonce(next_nonces, signer)
            payload = _valid_payload_for(kind, signer, nonce, i, users, profile)
            submitted_by_type[kind] = int(submitted_by_type.get(kind, 0)) + 1
            txs.append(_tx(kind, signer, nonce, payload))
            tx_kinds.append(kind)
            malformed_flags.append(False)

    submit_batch = getattr(executor, "submit_txs_batch", None)
    if callable(submit_batch):
        with (phase_probe.timed("mempool_submit_wall_ns") if phase_probe is not None else nullcontext()):
            results = submit_batch(txs, ingress="local_fixture", include_timings=phase_probe is not None)
        if phase_probe is not None and results:
            timings = None
            for result in reversed(results):
                if isinstance(result, dict) and isinstance(result.get("timings_ms"), dict):
                    timings = result.get("timings_ms")
                    break
            if isinstance(timings, dict):
                for field in MEMPOOL_SUBMIT_TIMING_FIELDS:
                    phase_probe.add_ms(field.replace("_ms", "_ns"), _phase_value_ms(timings.get(field)))
    else:
        results = []
        submit_start = time.perf_counter_ns()
        for tx_obj in txs:
            with (phase_probe.timed("mempool_submit_wall_ns") if phase_probe is not None else nullcontext()):
                results.append(executor.submit_tx(tx_obj, ingress="local_fixture"))
        if phase_probe is not None:
            phase_probe.add("tx_submit_total_wall_ns", time.perf_counter_ns() - submit_start)

    for kind, malformed, result in zip(tx_kinds, malformed_flags, results):
        if isinstance(result, dict) and result.get("ok"):
            admitted += 1
            if not malformed:
                accepted_by_type[kind] = int(accepted_by_type.get(kind, 0)) + 1
            continue
        if malformed:
            malformed_rejected += 1
        else:
            rejected += 1
        code = str((result or {}).get("error") or (result or {}).get("reason") or "rejected") if isinstance(result, dict) else "rejected"
        rejected_by_code[code] = int(rejected_by_code.get(code, 0)) + 1

    return {
        "admitted": admitted,
        "rejected": rejected,
        "rejected_by_code": rejected_by_code,
        "submitted_by_type": submitted_by_type,
        "accepted_by_type": accepted_by_type,
        "malformed_submitted": malformed_submitted,
        "malformed_rejected": malformed_rejected,
    }


def _mempool_size(executor: Any) -> int:
    mp = getattr(executor, "_mempool", None) or getattr(executor, "mempool", None)
    if mp is None:
        return 0
    fn = getattr(mp, "size", None)
    if callable(fn):
        return int(fn())
    return 0


def _fetch_mempool_candidates(executor: Any, *, max_txs: int) -> list[Json]:
    st = executor.read_state()
    candidate_height = int(st.get("height") or 0) + 1
    mp = getattr(executor, "_mempool", None) or getattr(executor, "mempool", None)
    if mp is None:
        return []
    try:
        policy = mp.selection_policy()
        rows = mp.fetch_for_block(limit=int(max_txs), policy=policy, candidate_height=candidate_height)
    except TypeError:
        rows = mp.fetch_for_block(limit=int(max_txs))
    except Exception:
        return []
    return [tx for tx in rows if isinstance(tx, dict)]


def _selected_type_counts(executor: Any, *, max_txs: int) -> dict[str, int]:
    out: dict[str, int] = {}
    for tx in _fetch_mempool_candidates(executor, max_txs=max_txs):
        t = str(tx.get("tx_type") or "UNKNOWN")
        out[t] = int(out.get(t, 0)) + 1
    return out


def _valid_candidate_count(executor: Any, *, max_txs: int) -> int:
    return len(_fetch_mempool_candidates(executor, max_txs=max_txs))


def _merge_submit_totals(dst: Json, src: Json) -> None:
    dst["admitted"] = int(dst.get("admitted") or 0) + int(src.get("admitted") or 0)
    dst["rejected"] = int(dst.get("rejected") or 0) + int(src.get("rejected") or 0)
    dst["malformed_submitted"] = int(dst.get("malformed_submitted") or 0) + int(src.get("malformed_submitted") or 0)
    dst["malformed_rejected"] = int(dst.get("malformed_rejected") or 0) + int(src.get("malformed_rejected") or 0)
    for k, v in dict(src.get("rejected_by_code") or {}).items():
        rejected = dst.setdefault("rejected_by_code", {})
        rejected[k] = int(rejected.get(k, 0)) + int(v)
    for k, v in dict(src.get("accepted_by_type") or {}).items():
        accepted = dst.setdefault("accepted_by_type", {})
        accepted[k] = int(accepted.get(k, 0)) + int(v)


def _submitted_count(result: Json) -> int:
    return int(result.get("admitted") or 0) + int(result.get("rejected") or 0) + int(result.get("malformed_submitted") or 0)


def _tx_count_semantics(*, requested_limit: int, selected_candidate_count: int, included_count: int) -> Json:
    derived = max(0, int(included_count) - int(selected_candidate_count))
    return {
        "max_txs_per_block_semantics": "mempool_candidate_limit_excludes_system_or_derived_txs",
        "requested_mempool_candidate_limit": int(requested_limit),
        "selected_candidate_tx_count": int(selected_candidate_count),
        "system_or_derived_txs_included": int(derived),
        "tx_count_overage_explained": bool(
            int(included_count) > int(requested_limit)
            and int(selected_candidate_count) <= int(requested_limit)
            and int(derived) > 0
        ),
    }


def _state_root(state: Json) -> str:
    from weall.runtime.state_hash import compute_state_root

    return str(compute_state_root(state))


def _produce_measured_block(executor: Any, *, max_txs: int, target_block_ms: int, execution_model: str = "deepcopy") -> Json:
    from weall.runtime.bounded_rollback import reset_rollback_diagnostics

    reset_rollback_diagnostics()
    probe = PhaseProbe()
    backlog_before = _mempool_size(executor)
    candidate_selection_start = time.perf_counter_ns()
    candidate_type_counts = _selected_type_counts(executor, max_txs=max_txs)
    candidate_selection_ns = time.perf_counter_ns() - candidate_selection_start
    start = time.perf_counter_ns()
    with _patched_block_builder_timing(executor, probe, execution_model=execution_model):
        candidate_start = time.perf_counter_ns()
        block, new_state, applied_ids, invalid_ids, err = executor.build_block_candidate(max_txs=int(max_txs), allow_empty=False)
        candidate_ns = time.perf_counter_ns() - candidate_start
    if block is None:
        return {
            "ok": False,
            "error": str(err or "no_block_candidate"),
            "mempool_backlog_before": backlog_before,
            "mempool_backlog_after": _mempool_size(executor),
            "block_total_wall_ms": _ms(time.perf_counter_ns() - start),
            "candidate_selection_wall_ms": _ms(candidate_selection_ns),
            "leader_block_build_wall_ms": _ms(candidate_ns),
            "leader_apply_or_execute_wall_ms": probe.ms("execution_time_ns"),
            "follower_apply_wall_ms": 0.0,
            "slow_observer_apply_wall_ms": 0.0,
            "state_root_wall_ms": probe.ms("state_root_time_ns"),
            "receipt_or_summary_wall_ms": 0.0,
            "leader_tx_loop_wall_ms": probe.ms("leader_tx_loop_time_ns") or probe.ms("execution_time_ns"),
            "follower_tx_loop_wall_ms": 0.0,
            "slow_observer_tx_loop_wall_ms": 0.0,
            "leader_receipt_build_wall_ms": probe.ms("leader_receipt_build_time_ns"),
            "follower_receipt_build_wall_ms": 0.0,
            "slow_observer_receipt_build_wall_ms": 0.0,
            "leader_state_root_wall_ms": probe.ms("leader_state_root_time_ns") or probe.ms("state_root_time_ns"),
            "follower_state_root_wall_ms": 0.0,
            "slow_observer_state_root_wall_ms": 0.0,
            "block_decode_or_materialize_wall_ms": probe.ms("block_decode_or_materialize_time_ns"),
            "replay_admission_wall_ms": 0.0,
            "rollback_journal_snapshot_wall_ms": 0.0,
            **_zero_rollback_journal_diagnostic_values(),
            **_tx_loop_microphase_values(probe, "leader"),
            **_zero_tx_loop_microphase_values("follower"),
            **_zero_tx_loop_microphase_values("slow_observer"),
            **_zero_replay_wrapper_phase_values("follower"),
            **_zero_replay_wrapper_phase_values("slow_observer"),
            **_tx_count_semantics(requested_limit=int(max_txs), selected_candidate_count=sum(int(v) for v in candidate_type_counts.values()), included_count=0),
            "total_block_production_time_ms": _ms(time.perf_counter_ns() - start),
            "execution_model": str(execution_model),
        }
    commit_start = time.perf_counter_ns()
    meta = executor.commit_block_candidate(block=block, new_state=new_state, applied_ids=applied_ids, invalid_ids=invalid_ids)
    persistence_ns = time.perf_counter_ns() - commit_start
    total_ns = time.perf_counter_ns() - start
    receipt_summary_start = time.perf_counter_ns()
    included_types: dict[str, int] = {}
    for tx in block.get("txs") if isinstance(block.get("txs"), list) else []:
        if not isinstance(tx, dict):
            continue
        t = str(tx.get("tx_type") or "UNKNOWN")
        included_types[t] = int(included_types.get(t, 0)) + 1
    receipts = block.get("receipts") if isinstance(block.get("receipts"), list) else []
    receipt_fingerprint = _fingerprint(receipts)
    receipt_copy = copy.deepcopy(receipts)
    receipt_summary_ns = time.perf_counter_ns() - receipt_summary_start
    included_count = len(block.get("txs") if isinstance(block.get("txs"), list) else [])
    selected_candidate_count = sum(int(v) for v in candidate_type_counts.values())
    tx_count_semantics = _tx_count_semantics(
        requested_limit=int(max_txs),
        selected_candidate_count=int(selected_candidate_count),
        included_count=int(included_count),
    )
    return {
        "_block_obj_for_replay": block,
        "ok": bool(getattr(meta, "ok", False)),
        "execution_model": str(execution_model),
        "error": str(getattr(meta, "error", "") or ""),
        "height": int(block.get("height") or 0),
        "block_id": str(block.get("block_id") or ""),
        "txs_included": included_count,
        "receipts_emitted": len(receipts),
        "accepted_tx_ids": [str(x) for x in applied_ids],
        "invalid_tx_ids": [str(x) for x in invalid_ids],
        "receipt_fingerprint": receipt_fingerprint,
        "receipts": receipt_copy,
        "tx_types_selected_before_block": candidate_type_counts,
        "tx_types_included": included_types,
        "mempool_backlog_before": backlog_before,
        "mempool_backlog_after": _mempool_size(executor),
        "block_total_wall_ms": _ms(total_ns),
        "candidate_selection_wall_ms": _ms(candidate_selection_ns),
        "leader_block_build_wall_ms": _ms(candidate_ns),
        "leader_apply_or_execute_wall_ms": probe.ms("execution_time_ns"),
        "follower_apply_wall_ms": 0.0,
        "slow_observer_apply_wall_ms": 0.0,
        "state_root_wall_ms": probe.ms("state_root_time_ns"),
        "receipt_or_summary_wall_ms": _ms(receipt_summary_ns),
        "leader_tx_loop_wall_ms": probe.ms("leader_tx_loop_time_ns") or probe.ms("execution_time_ns"),
        "follower_tx_loop_wall_ms": 0.0,
        "slow_observer_tx_loop_wall_ms": 0.0,
        "leader_receipt_build_wall_ms": probe.ms("leader_receipt_build_time_ns"),
        "follower_receipt_build_wall_ms": 0.0,
        "slow_observer_receipt_build_wall_ms": 0.0,
        "leader_state_root_wall_ms": probe.ms("leader_state_root_time_ns") or probe.ms("state_root_time_ns"),
        "follower_state_root_wall_ms": 0.0,
        "slow_observer_state_root_wall_ms": 0.0,
        "block_decode_or_materialize_wall_ms": probe.ms("block_decode_or_materialize_time_ns"),
        "replay_admission_wall_ms": 0.0,
        "rollback_journal_snapshot_wall_ms": 0.0,
        **_rollback_journal_diagnostic_values(),
        **_tx_loop_microphase_values(probe, "leader"),
        **_zero_tx_loop_microphase_values("follower"),
        **_zero_tx_loop_microphase_values("slow_observer"),
        **_zero_replay_wrapper_phase_values("follower"),
        **_zero_replay_wrapper_phase_values("slow_observer"),
        **tx_count_semantics,
        "proposal_construction_time_ms": max(
            0.0,
            round(_ms(candidate_ns) - probe.ms("block_admission_time_ns") - probe.ms("execution_time_ns") - probe.ms("state_root_time_ns") - probe.ms("helper_planning_time_ns"), 3),
        ),
        "candidate_total_time_ms": _ms(candidate_ns),
        "block_admission_time_ms": probe.ms("block_admission_time_ns"),
        "execution_time_ms": probe.ms("execution_time_ns"),
        "helper_planning_time_ms": probe.ms("helper_planning_time_ns"),
        "helper_execution_time_ms": 0.0,
        "deterministic_merge_time_ms": 0.0,
        "state_root_time_ms": probe.ms("state_root_time_ns"),
        "persistence_time_ms": _ms(persistence_ns),
        "gossip_commit_time_ms": None,
        "total_block_production_time_ms": _ms(total_ns),
        "target_block_interval_ms": int(target_block_ms),
        "target_exceeded": _ms(total_ns) > float(target_block_ms),
        "state_root": _state_root(new_state),
        "unmeasured_fields": ["real_network_gossip_latency", "remote_helper_execution_latency"],
    }


def _apply_to_follower(follower: Any, block: Json, *, role: str = "follower") -> Json:
    from weall.runtime.bounded_rollback import reset_rollback_diagnostics

    reset_rollback_diagnostics()
    start = time.perf_counter_ns()
    probe = PhaseProbe()
    try:
        with _patched_block_replay_timing(follower, probe, role=role):
            meta = follower.apply_block(block)
        ok = bool(getattr(meta, "ok", False))
        err = str(getattr(meta, "error", "") or "")
    except Exception as exc:
        ok = False
        err = str(exc)
    apply_time_ms = _ms(time.perf_counter_ns() - start)
    return {
        "ok": ok,
        "error": err,
        "apply_time_ms": apply_time_ms,
        "height": int(follower.read_state().get("height") or 0),
        "state_root": _state_root(follower.read_state()),
        "tx_loop_wall_ms": probe.ms(f"{role}_tx_loop_time_ns"),
        "receipt_build_wall_ms": probe.ms(f"{role}_receipt_build_time_ns"),
        "state_root_wall_ms": probe.ms(f"{role}_state_root_time_ns"),
        "block_decode_or_materialize_wall_ms": probe.ms("block_decode_or_materialize_time_ns"),
        "replay_admission_wall_ms": probe.ms("replay_admission_time_ns"),
        "rollback_journal_snapshot_wall_ms": probe.ms("rollback_journal_snapshot_time_ns"),
        "tx_decode_or_normalize_wall_ms": probe.ms(f"{role}_tx_decode_or_normalize_time_ns"),
        "tx_id_or_hash_wall_ms": probe.ms(f"{role}_tx_id_or_hash_time_ns"),
        "domain_dispatch_wall_ms": _domain_dispatch_ms(probe, role),
        "domain_apply_wall_ms": probe.ms(f"{role}_domain_apply_time_ns"),
        "rollback_tracking_wall_ms": probe.ms(f"{role}_rollback_tracking_time_ns"),
        **_replay_wrapper_phase_values(probe, role=role, apply_time_ms=apply_time_ms),
        **_rollback_journal_diagnostic_values(),
    }


def _copy_replay_microphases(block: Json, replay_result: Json, *, prefix: str) -> None:
    block[f"{prefix}_tx_decode_or_normalize_wall_ms"] = _phase_value_ms(replay_result.get("tx_decode_or_normalize_wall_ms"))
    block[f"{prefix}_tx_id_or_hash_wall_ms"] = _phase_value_ms(replay_result.get("tx_id_or_hash_wall_ms"))
    block[f"{prefix}_domain_dispatch_wall_ms"] = _phase_value_ms(replay_result.get("domain_dispatch_wall_ms"))
    block[f"{prefix}_domain_apply_wall_ms"] = _phase_value_ms(replay_result.get("domain_apply_wall_ms"))
    block[f"{prefix}_rollback_tracking_wall_ms"] = _phase_value_ms(replay_result.get("rollback_tracking_wall_ms"))
    for field in REPLAY_WRAPPER_PHASES:
        block[f"{prefix}_{field}"] = _phase_value_ms(replay_result.get(field))


def _summary(blocks: list[Json]) -> Json:
    totals = [float(b.get("total_block_production_time_ms") or 0.0) for b in blocks if b.get("ok")]
    if not totals:
        return {"count": 0}
    ordered = sorted(totals)
    def percentile(p: float) -> float:
        if len(ordered) == 1:
            return ordered[0]
        k = (len(ordered) - 1) * p
        f = int(k)
        c = min(f + 1, len(ordered) - 1)
        if f == c:
            return ordered[f]
        return ordered[f] + (ordered[c] - ordered[f]) * (k - f)
    return {
        "count": len(totals),
        "avg_ms": round(statistics.mean(totals), 3),
        "max_ms": round(max(totals), 3),
        "p95_ms": round(percentile(0.95), 3),
        "p99_ms": round(percentile(0.99), 3),
        "target_exceeded_count": sum(1 for b in blocks if b.get("target_exceeded")),
    }


def run_profile(profile: str, *, users_n: int, blocks_n: int, max_txs_per_block: int, txs_per_block_feed: int, target_block_ms: int, helper_fast_path: bool, restart_during_load: bool, execution_model: str = "deepcopy", chain_id_override: str | None = None, sustain_load: bool = False) -> Json:
    profile_start_ns = time.perf_counter_ns()
    profile_probe = PhaseProbe()
    execution_model = str(execution_model or "deepcopy")
    chain_id = str(chain_id_override or f"block-schedule-survivability-{profile}-{execution_model}")
    with profile_probe.timed("user_prepare_wall_ns"):
        users = [f"@load{i:03d}" for i in range(max(3, int(users_n)))]
    with profile_probe.timed("setup_wall_ns"):
        tempdir = tempfile.mkdtemp(prefix=f"weall-block-schedule-{profile}-{execution_model}-")
        leader = _make_executor(str(Path(tempdir) / "leader.db"), node_id="@leader", chain_id=chain_id, helper_fast_path=helper_fast_path)
        follower = _make_executor(str(Path(tempdir) / "follower.db"), node_id="@follower", chain_id=chain_id, helper_fast_path=False)
        slow_observer = _make_executor(str(Path(tempdir) / "slow-observer.db"), node_id="@slow-observer", chain_id=chain_id, helper_fast_path=False)
        seed = _seed_state(leader, users)
        _clone_seed_to_follower(follower, seed)
        _clone_seed_to_follower(slow_observer, seed)
    next_nonces = {u: 2 for u in users}
    blocks: list[Json] = []
    follower_results: list[Json] = []
    slow_queue: list[tuple[int, Json]] = []
    restart_result: Json = {}
    aggregate_submit = {"admitted": 0, "rejected": 0, "malformed_submitted": 0, "malformed_rejected": 0, "rejected_by_code": {}, "accepted_by_type": {}}

    with profile_probe.timed("block_loop_wall_ns"):
        for block_i in range(int(blocks_n)):
            initial_pre_refill_mempool_size = _mempool_size(leader)
            submit_result = _submit_profile_load(
                leader,
                profile=profile,
                users=users,
                next_nonces=next_nonces,
                count=int(txs_per_block_feed),
                phase_probe=profile_probe,
            )
            block_submit_totals: Json = {"admitted": 0, "rejected": 0, "malformed_submitted": 0, "malformed_rejected": 0, "rejected_by_code": {}, "accepted_by_type": {}}
            _merge_submit_totals(block_submit_totals, submit_result)
            per_block_refill_submitted = 0
            per_block_refill_admitted = 0
            per_block_refill_rejected = 0
            per_block_refill_attempts = 0

            valid_candidate_count = _valid_candidate_count(leader, max_txs=max_txs_per_block)
            if sustain_load:
                # Existing mode submits txs_per_block_feed once per block.  Sustained mode
                # keeps that behavior, then deterministically tops up until the block can
                # actually select max_txs_per_block candidates, or the bounded attempt budget
                # is exhausted.  This is load generation only; candidate selection and replay
                # still use normal consensus paths.
                max_attempts = max(2, int(blocks_n) + 4)
                while valid_candidate_count < int(max_txs_per_block) and per_block_refill_attempts < max_attempts:
                    deficit = int(max_txs_per_block) - int(valid_candidate_count)
                    refill_count = max(deficit, max(1, int(max_txs_per_block) // 4))
                    refill = _submit_profile_load(
                        leader,
                        profile=profile,
                        users=users,
                        next_nonces=next_nonces,
                        count=int(refill_count),
                        phase_probe=profile_probe,
                    )
                    per_block_refill_attempts += 1
                    per_block_refill_submitted += _submitted_count(refill)
                    per_block_refill_admitted += int(refill.get("admitted") or 0)
                    per_block_refill_rejected += int(refill.get("rejected") or 0) + int(refill.get("malformed_rejected") or 0)
                    _merge_submit_totals(block_submit_totals, refill)
                    valid_candidate_count = _valid_candidate_count(leader, max_txs=max_txs_per_block)

            _merge_submit_totals(aggregate_submit, block_submit_totals)
            pre_block_mempool_size = _mempool_size(leader)
            per_block_target_met = bool(valid_candidate_count >= int(max_txs_per_block))

            measured = _produce_measured_block(leader, max_txs=max_txs_per_block, target_block_ms=target_block_ms, execution_model=execution_model)
            measured["block_index"] = block_i
            measured["initial_pre_refill_mempool_size"] = int(initial_pre_refill_mempool_size)
            measured["pre_block_mempool_size"] = int(pre_block_mempool_size)
            measured["post_block_mempool_size"] = int(measured.get("mempool_backlog_after") or _mempool_size(leader))
            measured["valid_candidate_count"] = int(valid_candidate_count)
            measured["admitted_before_block_count"] = int(block_submit_totals.get("admitted") or 0)
            measured["rejected_before_block_count"] = int(block_submit_totals.get("rejected") or 0) + int(block_submit_totals.get("malformed_rejected") or 0)
            measured["per_block_refill_submitted"] = int(per_block_refill_submitted)
            measured["per_block_refill_admitted"] = int(per_block_refill_admitted)
            measured["per_block_refill_rejected"] = int(per_block_refill_rejected)
            measured["per_block_refill_attempts"] = int(per_block_refill_attempts)
            measured["per_block_target_met"] = bool(per_block_target_met)
            measured["sustain_load"] = bool(sustain_load)
            measured["txs_admitted_this_round"] = int(block_submit_totals.get("admitted") or 0)
            measured["txs_rejected_this_round"] = int(block_submit_totals.get("rejected") or 0)
            measured["rejected_by_code_this_round"] = block_submit_totals.get("rejected_by_code") or {}
            blocks.append(measured)
            if not measured.get("ok"):
                continue
            block_obj = measured.pop("_block_obj_for_replay", None)
            if not isinstance(block_obj, dict):
                block_obj = leader.read_state().get("blocks", {}).get(str(measured.get("height")))
            if not isinstance(block_obj, dict):
                # Fallback only: optimized harnesses should use the in-memory block
                # returned by _produce_measured_block to avoid JSON DB materialization
                # in throughput diagnostics.
                import sqlite3
                con = sqlite3.connect(str(Path(tempdir) / "leader.db"))
                con.row_factory = sqlite3.Row
                row = con.execute("SELECT block_json FROM blocks WHERE height=?", (int(measured.get("height") or 0),)).fetchone()
                con.close()
                block_obj = json.loads(row["block_json"]) if row else {}
            with profile_probe.timed("follower_apply_wall_ns"):
                fr = _apply_to_follower(follower, block_obj, role="follower")
            measured["follower_apply_wall_ms"] = _phase_value_ms(fr.get("apply_time_ms"))
            measured["follower_tx_loop_wall_ms"] = _phase_value_ms(fr.get("tx_loop_wall_ms"))
            measured["follower_receipt_build_wall_ms"] = _phase_value_ms(fr.get("receipt_build_wall_ms"))
            measured["follower_state_root_wall_ms"] = _phase_value_ms(fr.get("state_root_wall_ms"))
            measured["block_decode_or_materialize_wall_ms"] = round(float(measured.get("block_decode_or_materialize_wall_ms") or 0.0) + _phase_value_ms(fr.get("block_decode_or_materialize_wall_ms")), 3)
            measured["replay_admission_wall_ms"] = round(float(measured.get("replay_admission_wall_ms") or 0.0) + _phase_value_ms(fr.get("replay_admission_wall_ms")), 3)
            measured["rollback_journal_snapshot_wall_ms"] = round(float(measured.get("rollback_journal_snapshot_wall_ms") or 0.0) + _phase_value_ms(fr.get("rollback_journal_snapshot_wall_ms")), 3)
            _add_rollback_journal_diagnostics(measured, fr)
            _copy_replay_microphases(measured, fr, prefix="follower")
            follower_results.append(fr)
            slow_queue.append((block_i, block_obj))
            if len(slow_queue) >= 2:
                slow_idx, slow_block_obj = slow_queue.pop(0)
                with profile_probe.timed("slow_observer_apply_wall_ns"):
                    sr = _apply_to_follower(slow_observer, slow_block_obj, role="slow_observer")
                if 0 <= slow_idx < len(blocks):
                    blocks[slow_idx]["slow_observer_apply_wall_ms"] = _phase_value_ms(sr.get("apply_time_ms"))
                    blocks[slow_idx]["slow_observer_tx_loop_wall_ms"] = _phase_value_ms(sr.get("tx_loop_wall_ms"))
                    blocks[slow_idx]["slow_observer_receipt_build_wall_ms"] = _phase_value_ms(sr.get("receipt_build_wall_ms"))
                    blocks[slow_idx]["slow_observer_state_root_wall_ms"] = _phase_value_ms(sr.get("state_root_wall_ms"))
                    blocks[slow_idx]["block_decode_or_materialize_wall_ms"] = round(float(blocks[slow_idx].get("block_decode_or_materialize_wall_ms") or 0.0) + _phase_value_ms(sr.get("block_decode_or_materialize_wall_ms")), 3)
                    blocks[slow_idx]["replay_admission_wall_ms"] = round(float(blocks[slow_idx].get("replay_admission_wall_ms") or 0.0) + _phase_value_ms(sr.get("replay_admission_wall_ms")), 3)
                    blocks[slow_idx]["rollback_journal_snapshot_wall_ms"] = round(float(blocks[slow_idx].get("rollback_journal_snapshot_wall_ms") or 0.0) + _phase_value_ms(sr.get("rollback_journal_snapshot_wall_ms")), 3)
                    _add_rollback_journal_diagnostics(blocks[slow_idx], sr)
                    _copy_replay_microphases(blocks[slow_idx], sr, prefix="slow_observer")

            if restart_during_load and block_i == int(blocks_n) // 2:
                with profile_probe.timed("restart_replay_wall_ns"):
                    before = {"height": int(leader.read_state().get("height") or 0), "state_root": _state_root(leader.read_state())}
                    leader = _make_executor(str(Path(tempdir) / "leader.db"), node_id="@leader", chain_id=chain_id, helper_fast_path=helper_fast_path)
                    after = {"height": int(leader.read_state().get("height") or 0), "state_root": _state_root(leader.read_state())}
                    restart_result = {"performed": True, "before": before, "after": after, "same_state_root": before["state_root"] == after["state_root"]}

        for slow_idx, block_obj in slow_queue:
            with profile_probe.timed("slow_observer_apply_wall_ns"):
                sr = _apply_to_follower(slow_observer, block_obj, role="slow_observer")
            if 0 <= slow_idx < len(blocks):
                blocks[slow_idx]["slow_observer_apply_wall_ms"] = _phase_value_ms(sr.get("apply_time_ms"))
                blocks[slow_idx]["slow_observer_tx_loop_wall_ms"] = _phase_value_ms(sr.get("tx_loop_wall_ms"))
                blocks[slow_idx]["slow_observer_receipt_build_wall_ms"] = _phase_value_ms(sr.get("receipt_build_wall_ms"))
                blocks[slow_idx]["slow_observer_state_root_wall_ms"] = _phase_value_ms(sr.get("state_root_wall_ms"))
                blocks[slow_idx]["block_decode_or_materialize_wall_ms"] = round(float(blocks[slow_idx].get("block_decode_or_materialize_wall_ms") or 0.0) + _phase_value_ms(sr.get("block_decode_or_materialize_wall_ms")), 3)
                blocks[slow_idx]["replay_admission_wall_ms"] = round(float(blocks[slow_idx].get("replay_admission_wall_ms") or 0.0) + _phase_value_ms(sr.get("replay_admission_wall_ms")), 3)
                blocks[slow_idx]["rollback_journal_snapshot_wall_ms"] = round(float(blocks[slow_idx].get("rollback_journal_snapshot_wall_ms") or 0.0) + _phase_value_ms(sr.get("rollback_journal_snapshot_wall_ms")), 3)
                _add_rollback_journal_diagnostics(blocks[slow_idx], sr)
                _copy_replay_microphases(blocks[slow_idx], sr, prefix="slow_observer")
    leader_root = _state_root(leader.read_state())
    follower_root = _state_root(follower.read_state())
    slow_root = _state_root(slow_observer.read_state())
    profile_total_wall_ms = _ms(time.perf_counter_ns() - profile_start_ns)
    result = {
        "profile": profile,
        "chain_id": chain_id,
        "tempdir": tempdir,
        "users": len(users),
        "blocks_requested": int(blocks_n),
        "max_txs_per_block": int(max_txs_per_block),
        "txs_per_block_feed": int(txs_per_block_feed),
        "txs_per_block_feed_semantics": (
            "per_block_initial_submit_count_with_deterministic_candidate_top_up"
            if bool(sustain_load)
            else "per_block_initial_submit_count_not_candidate_guarantee"
        ),
        "sustain_load": bool(sustain_load),
        "target_block_interval_ms": int(target_block_ms),
        "helper_fast_path_requested": bool(helper_fast_path),
        "execution_model": execution_model,
        "profile_total_wall_ms": profile_total_wall_ms,
        "setup_wall_ms": profile_probe.ms("setup_wall_ns"),
        "user_prepare_wall_ms": profile_probe.ms("user_prepare_wall_ns"),
        "tx_generation_wall_ms": profile_probe.ms("tx_generation_wall_ns"),
        "mempool_submit_wall_ms": profile_probe.ms("mempool_submit_wall_ns"),
        "tx_submit_total_wall_ms": profile_probe.ms("tx_submit_total_wall_ns"),
        "tx_signature_verify_wall_ms": profile_probe.ms("tx_signature_verify_wall_ns"),
        "tx_canonicalize_or_hash_wall_ms": profile_probe.ms("tx_canonicalize_or_hash_wall_ns"),
        "tx_nonce_check_wall_ms": profile_probe.ms("tx_nonce_check_wall_ns"),
        "tx_mempool_insert_wall_ms": profile_probe.ms("tx_mempool_insert_wall_ns"),
        "tx_reject_wall_ms": profile_probe.ms("tx_reject_wall_ns"),
        "tx_duplicate_check_wall_ms": profile_probe.ms("tx_duplicate_check_wall_ns"),
        "block_loop_wall_ms": profile_probe.ms("block_loop_wall_ns"),
        "follower_apply_wall_ms": profile_probe.ms("follower_apply_wall_ns"),
        "slow_observer_apply_wall_ms": profile_probe.ms("slow_observer_apply_wall_ns"),
        "restart_replay_wall_ms": profile_probe.ms("restart_replay_wall_ns"),
        "evidence_write_wall_ms": 0.0,
        "aggregate_submit": aggregate_submit,
        "block_measurements": blocks,
        "latency_summary": _summary(blocks),
        "follower_apply_results": follower_results,
        "convergence": {
            "leader_height": int(leader.read_state().get("height") or 0),
            "follower_height": int(follower.read_state().get("height") or 0),
            "slow_observer_height": int(slow_observer.read_state().get("height") or 0),
            "leader_state_root": leader_root,
            "follower_state_root": follower_root,
            "slow_observer_state_root": slow_root,
            "leader_state_fingerprint": _fingerprint(leader.read_state()),
            "follower_state_fingerprint": _fingerprint(follower.read_state()),
            "slow_observer_state_fingerprint": _fingerprint(slow_observer.read_state()),
            "all_nodes_converged": leader_root == follower_root == slow_root,
        },
        "restart_during_load": restart_result or {"performed": False},
    }
    result["profile_bottleneck_summary"] = _profile_bottleneck_summary(result)
    return result



def _project_block_for_equivalence(block: Json) -> Json:
    return {
        "ok": bool(block.get("ok")),
        "error": str(block.get("error") or ""),
        "height": int(block.get("height") or 0),
        "block_id": str(block.get("block_id") or ""),
        "txs_included": int(block.get("txs_included") or 0),
        "receipts_emitted": int(block.get("receipts_emitted") or 0),
        "accepted_tx_ids": list(block.get("accepted_tx_ids") or []),
        "invalid_tx_ids": list(block.get("invalid_tx_ids") or []),
        "receipt_fingerprint": str(block.get("receipt_fingerprint") or ""),
        "receipts": copy.deepcopy(block.get("receipts") or []),
        "tx_types_included": dict(block.get("tx_types_included") or {}),
        "state_root": str(block.get("state_root") or ""),
    }


def _project_profile_for_equivalence(profile: Json) -> Json:
    convergence = dict(profile.get("convergence") or {})
    return {
        "profile": str(profile.get("profile") or ""),
        "chain_id": str(profile.get("chain_id") or ""),
        "aggregate_submit": copy.deepcopy(profile.get("aggregate_submit") or {}),
        "blocks": [
            _project_block_for_equivalence(b)
            for b in list(profile.get("block_measurements") or [])
            if isinstance(b, dict)
        ],
        "follower_apply_results": [
            {
                "ok": bool(r.get("ok")),
                "error": str(r.get("error") or ""),
                "height": int(r.get("height") or 0),
                "state_root": str(r.get("state_root") or ""),
            }
            for r in list(profile.get("follower_apply_results") or [])
            if isinstance(r, dict)
        ],
        "convergence": {
            "leader_height": int(convergence.get("leader_height") or 0),
            "follower_height": int(convergence.get("follower_height") or 0),
            "slow_observer_height": int(convergence.get("slow_observer_height") or 0),
            "leader_state_root": str(convergence.get("leader_state_root") or ""),
            "follower_state_root": str(convergence.get("follower_state_root") or ""),
            "slow_observer_state_root": str(convergence.get("slow_observer_state_root") or ""),
            "leader_state_fingerprint": str(convergence.get("leader_state_fingerprint") or ""),
            "follower_state_fingerprint": str(convergence.get("follower_state_fingerprint") or ""),
            "slow_observer_state_fingerprint": str(convergence.get("slow_observer_state_fingerprint") or ""),
            "all_nodes_converged": bool(convergence.get("all_nodes_converged")),
        },
    }


def _compare_execution_model_results(results: list[Json]) -> Json:
    by_profile: dict[str, dict[str, Json]] = {}
    for result in results:
        profile = str(result.get("profile") or "")
        model = str(result.get("execution_model") or "")
        by_profile.setdefault(profile, {})[model] = result

    profile_results: dict[str, Json] = {}
    ok_all = True
    for profile, models in sorted(by_profile.items()):
        deepcopy_result = models.get("deepcopy")
        rollback_result = models.get("bounded_rollback")
        if not isinstance(deepcopy_result, dict) or not isinstance(rollback_result, dict):
            ok_all = False
            profile_results[profile] = {
                "ok": False,
                "reason": "missing_model_result",
                "models_present": sorted(models.keys()),
            }
            continue
        left = _project_profile_for_equivalence(deepcopy_result)
        right = _project_profile_for_equivalence(rollback_result)
        equal = left == right
        if not equal:
            ok_all = False
        mismatched_sections: list[str] = []
        for key in sorted(set(left.keys()) | set(right.keys())):
            if left.get(key) != right.get(key):
                mismatched_sections.append(key)
        profile_results[profile] = {
            "ok": bool(equal),
            "deepcopy_fingerprint": _fingerprint(left),
            "bounded_rollback_fingerprint": _fingerprint(right),
            "mismatched_sections": mismatched_sections,
        }
    return {
        "ok": bool(ok_all),
        "profiles": profile_results,
        "models_compared": ["deepcopy", "bounded_rollback"],
        "comparison_fields": [
            "chain_id",
            "aggregate_submit",
            "accepted_tx_ids",
            "invalid_tx_ids",
            "receipts",
            "receipt_fingerprint",
            "state_root",
            "follower_apply_results",
            "final_state_fingerprint",
            "convergence",
        ],
    }

def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--profile", choices=["light", "active", "adversarial", "network", "all"], default="light")
    parser.add_argument("--users", type=int, default=0)
    parser.add_argument("--blocks", type=int, default=0)
    parser.add_argument("--max-txs-per-block", type=int, default=0)
    parser.add_argument("--txs-per-block-feed", type=int, default=0)
    parser.add_argument("--target-block-ms", type=int, default=DEFAULT_TARGET_BLOCK_MS)
    parser.add_argument("--helper-fast-path", action="store_true")
    parser.add_argument("--execution-model", choices=["deepcopy", "bounded_rollback", "compare"], default="bounded_rollback")
    parser.add_argument("--restart-during-load", action="store_true", default=True)
    parser.add_argument("--sustain-load", action="store_true", help="deterministically refill mempool before each block until candidate target is met")
    parser.add_argument("--out", default="")
    args = parser.parse_args(argv)

    profiles = ["light", "active", "adversarial", "network"] if args.profile == "all" else [args.profile]
    models = ["deepcopy", "bounded_rollback"] if args.execution_model == "compare" else [args.execution_model]
    results = []
    for profile in profiles:
        defaults = PROFILE_DEFAULTS[profile]
        for model in models:
            results.append(
                run_profile(
                    profile,
                    users_n=args.users or defaults["users"],
                    blocks_n=args.blocks or defaults["blocks"],
                    max_txs_per_block=args.max_txs_per_block or defaults["max_txs_per_block"],
                    txs_per_block_feed=args.txs_per_block_feed or defaults["txs_per_block_feed"],
                    target_block_ms=args.target_block_ms,
                    helper_fast_path=args.helper_fast_path,
                    restart_during_load=bool(args.restart_during_load),
                    execution_model=model,
                    sustain_load=bool(args.sustain_load),
                    chain_id_override=(
                        f"block-schedule-survivability-{profile}-compare"
                        if args.execution_model == "compare"
                        else None
                    ),
                )
            )
    compare_equivalence = (
        _compare_execution_model_results(results)
        if args.execution_model == "compare"
        else {"ok": True, "skipped": True}
    )
    artifact: Json = {
        "artifact": "block_schedule_survivability_rehearsal_evidence_v1_5",
        "generated_at_ms": _now_ms(),
        "repo_root": str(REPO_ROOT),
        "budget_artifact": "specs/block_schedule_survivability_budget_v1_5.json",
        "execution_models": models,
        "profiles": results,
        "compare_equivalence": compare_equivalence,
        "evidence_write_wall_ms": 0.0,
        "bottleneck_summary": _artifact_bottleneck_summary(results, evidence_write_wall_ms=0.0),
    }
    out = Path(args.out) if args.out else REPO_ROOT / "rehearsal-evidence" / f"block_schedule_survivability_{_now_ms()}.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    evidence_write_start = time.perf_counter_ns()
    out.write_text(json.dumps(artifact, indent=2, sort_keys=True), encoding="utf-8")
    evidence_write_wall_ms = _ms(time.perf_counter_ns() - evidence_write_start)
    for profile_result in results:
        profile_result["evidence_write_wall_ms"] = evidence_write_wall_ms
        profile_result["profile_bottleneck_summary"] = _profile_bottleneck_summary(profile_result)
    artifact["evidence_write_wall_ms"] = evidence_write_wall_ms
    artifact["bottleneck_summary"] = _artifact_bottleneck_summary(results, evidence_write_wall_ms=evidence_write_wall_ms)
    out.write_text(json.dumps(artifact, indent=2, sort_keys=True), encoding="utf-8")
    print(str(out))
    if args.execution_model == "compare" and not bool(compare_equivalence.get("ok")):
        print("ERROR: execution model equivalence mismatch", file=sys.stderr)
        return 2
    # A non-zero exit is reserved for harness/runtime/equivalence failure. Cadence misses are evidence.
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
