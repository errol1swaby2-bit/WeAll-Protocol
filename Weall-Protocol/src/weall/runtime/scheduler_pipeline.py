from __future__ import annotations

"""Deterministic system scheduler pipeline shared by block build/replay paths.

This module is the audit boundary for scheduler ordering. It preserves the
currently implemented ordering exactly while making leader/replay sequencing easy
to compare in one file. Future semantic cleanup should first collapse the leader
and follower profiles once regression tests prove the block/state roots remain
stable.
"""

from typing import Any

from weall.runtime.dispute_engine import tick_dispute_lifecycle
from weall.runtime.gov_engine import tick_governance_lifecycle
from weall.runtime.node_operator_scheduler import schedule_node_operator_system_txs
from weall.runtime.poh.async_scheduler import schedule_poh_async_system_txs
from weall.runtime.poh.live_scheduler import schedule_poh_live_system_txs
from weall.runtime.poh.tier2_scheduler import schedule_poh_tier2_system_txs
from weall.runtime.reputation_accrual import schedule_reputation_accrual_system_txs
from weall.runtime.system_tx_engine import prune_emitted_system_queue, system_tx_emitter

Json = dict[str, Any]


def _executor_symbol(name: str, fallback: Any) -> Any:
    """Return the current public executor-module symbol when available.

    This preserves pre-refactor monkeypatch and fail-closed test behavior while
    scheduler sequencing lives in this extracted audit boundary.
    """
    try:
        from weall.runtime import executor as _executor_mod

        return getattr(_executor_mod, name, fallback)
    except Exception:
        return fallback


def run_core_schedulers(state: Json, *, next_height: int) -> None:
    _executor_symbol("schedule_poh_async_system_txs", schedule_poh_async_system_txs)(state, next_height=next_height)
    _executor_symbol("schedule_poh_tier2_system_txs", schedule_poh_tier2_system_txs)(state, next_height=next_height)
    _executor_symbol("schedule_poh_live_system_txs", schedule_poh_live_system_txs)(state, next_height=next_height)
    _executor_symbol("schedule_node_operator_system_txs", schedule_node_operator_system_txs)(state, next_height=next_height)
    _executor_symbol("schedule_reputation_accrual_system_txs", schedule_reputation_accrual_system_txs)(state, next_height=next_height)


def run_leader_pre_schedulers(state: Json, *, next_height: int) -> None:
    run_core_schedulers(state, next_height=next_height)
    _executor_symbol("tick_governance_lifecycle", tick_governance_lifecycle)(state, next_height=next_height)
    _executor_symbol("tick_dispute_lifecycle", tick_dispute_lifecycle)(state, next_height=next_height)


def run_leader_post_schedulers(state: Json, *, next_height: int) -> None:
    run_core_schedulers(state, next_height=next_height)


def run_replay_pre_schedulers(state: Json, *, next_height: int) -> None:
    # Preserve existing replay behavior. Do not add governance/dispute here until
    # replay/root regression tests intentionally approve the semantic change.
    run_core_schedulers(state, next_height=next_height)


def run_replay_post_schedulers(state: Json, *, next_height: int) -> None:
    run_core_schedulers(state, next_height=next_height)


def emit_system_txs(
    state: Json,
    tx_index: Any,
    *,
    next_height: int,
    phase: str,
    proposer: str = "",
) -> list[Any]:
    emitter = _executor_symbol("system_tx_emitter", system_tx_emitter)
    return emitter(
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


def prune_emitted(state: Json) -> None:
    _executor_symbol("prune_emitted_system_queue", prune_emitted_system_queue)(state)
