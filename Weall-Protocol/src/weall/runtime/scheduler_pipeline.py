from __future__ import annotations

"""Deterministic system scheduler pipeline shared by block build/replay paths.

This module is the audit boundary for scheduler ordering. It preserves the
currently implemented ordering exactly while making leader/replay sequencing easy
to compare in one file. Future semantic cleanup should first collapse the leader
and follower profiles once regression tests prove the block/state roots remain
stable.
"""

from typing import Any

from weall.runtime.runtime_context import SchedulerSet

Json = dict[str, Any]


def _scheduler_set(scheduler_set: SchedulerSet | None = None) -> SchedulerSet:
    return scheduler_set if isinstance(scheduler_set, SchedulerSet) else SchedulerSet.defaults()


def run_core_schedulers(state: Json, *, next_height: int, scheduler_set: SchedulerSet | None = None) -> None:
    schedulers = _scheduler_set(scheduler_set)
    schedulers.schedule_poh_async_system_txs(state, next_height=next_height)
    schedulers.schedule_poh_tier2_system_txs(state, next_height=next_height)
    schedulers.schedule_poh_live_system_txs(state, next_height=next_height)
    schedulers.schedule_node_operator_system_txs(state, next_height=next_height)
    schedulers.schedule_reputation_accrual_system_txs(state, next_height=next_height)


def run_leader_pre_schedulers(state: Json, *, next_height: int, scheduler_set: SchedulerSet | None = None) -> None:
    schedulers = _scheduler_set(scheduler_set)
    run_core_schedulers(state, next_height=next_height, scheduler_set=schedulers)
    schedulers.tick_governance_lifecycle(state, next_height=next_height)
    schedulers.tick_dispute_lifecycle(state, next_height=next_height)


def run_leader_post_schedulers(state: Json, *, next_height: int, scheduler_set: SchedulerSet | None = None) -> None:
    run_core_schedulers(state, next_height=next_height, scheduler_set=scheduler_set)


def run_replay_pre_schedulers(state: Json, *, next_height: int, scheduler_set: SchedulerSet | None = None) -> None:
    # Preserve existing replay behavior. Do not add governance/dispute here until
    # replay/root regression tests intentionally approve the semantic change.
    run_core_schedulers(state, next_height=next_height, scheduler_set=scheduler_set)


def run_replay_post_schedulers(state: Json, *, next_height: int, scheduler_set: SchedulerSet | None = None) -> None:
    run_core_schedulers(state, next_height=next_height, scheduler_set=scheduler_set)


def emit_system_txs(
    state: Json,
    tx_index: Any,
    *,
    next_height: int,
    phase: str,
    proposer: str = "",
    scheduler_set: SchedulerSet | None = None,
) -> list[Any]:
    schedulers = _scheduler_set(scheduler_set)
    return schedulers.system_tx_emitter(
        state,
        tx_index,
        next_height=next_height,
        phase=phase,
        proposer=proposer,
    )


def queue_item_phase(state: Json, queue_id: str) -> str:
    try:
        q = state.get("system_queue")
        if not isinstance(q, list):
            return ""
        qid = str(queue_id or "").strip()
        if not qid:
            return ""
        for obj in q:
            if not isinstance(obj, dict):
                continue
            if str(obj.get("queue_id") or "").strip() == qid:
                return str(obj.get("phase") or "").strip().lower()
        return ""
    except Exception:
        return ""


def prune_emitted(state: Json, *, scheduler_set: SchedulerSet | None = None) -> None:
    schedulers = _scheduler_set(scheduler_set)
    schedulers.prune_emitted_system_queue(state)
