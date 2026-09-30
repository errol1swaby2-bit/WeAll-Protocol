from __future__ import annotations

"""Explicit runtime dependency objects for extracted executor modules.

The first executor split intentionally preserved behavior by delegating from
``WeAllExecutor`` into smaller modules.  This module is the second-stage cleanup
boundary: extracted modules should receive dependencies through these small
objects instead of reaching back into ``weall.runtime.executor`` on every call.

The default factories still mirror public executor-module monkeypatches so the
existing fail-closed regression tests keep exercising the same surface while the
runtime moves toward explicit dependency injection.
"""

from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from weall.runtime.account_recovery_scheduler import schedule_account_recovery_system_txs
from weall.runtime.dispute_engine import tick_dispute_lifecycle
from weall.runtime.domain_apply import apply_tx_atomic_meta
from weall.runtime.gov_engine import tick_governance_lifecycle
from weall.runtime.node_operator_scheduler import schedule_node_operator_system_txs
from weall.runtime.poh.async_scheduler import schedule_poh_async_system_txs
from weall.runtime.poh.live_scheduler import schedule_poh_live_system_txs
from weall.runtime.poh.tier2_scheduler import schedule_poh_tier2_system_txs
from weall.runtime.reputation_accrual import schedule_reputation_accrual_system_txs
from weall.runtime.system_tx_engine import prune_emitted_system_queue, system_tx_emitter


@dataclass(frozen=True)
class SchedulerSet:
    """Deterministic scheduler/emitter dependency set.

    Keeping these callables in one object makes leader/replay scheduler ordering
    auditable without allowing the scheduler pipeline to import the executor
    facade directly.
    """

    schedule_account_recovery_system_txs: Callable[..., Any] = schedule_account_recovery_system_txs
    schedule_poh_async_system_txs: Callable[..., Any] = schedule_poh_async_system_txs
    schedule_poh_tier2_system_txs: Callable[..., Any] = schedule_poh_tier2_system_txs
    schedule_poh_live_system_txs: Callable[..., Any] = schedule_poh_live_system_txs
    schedule_node_operator_system_txs: Callable[..., Any] = schedule_node_operator_system_txs
    schedule_reputation_accrual_system_txs: Callable[..., Any] = (
        schedule_reputation_accrual_system_txs
    )
    tick_governance_lifecycle: Callable[..., Any] = tick_governance_lifecycle
    tick_dispute_lifecycle: Callable[..., Any] = tick_dispute_lifecycle
    system_tx_emitter: Callable[..., Any] = system_tx_emitter
    prune_emitted_system_queue: Callable[..., Any] = prune_emitted_system_queue

    @classmethod
    def defaults(cls) -> SchedulerSet:
        return cls()

    @classmethod
    def from_executor_module(cls) -> SchedulerSet:
        """Mirror patched public executor symbols at the facade boundary.

        Several existing tests monkeypatch ``weall.runtime.executor`` because the
        scheduler functions lived there before the module split.  This keeps that
        compatibility localized to context construction instead of hidden inside
        the scheduler pipeline itself.
        """
        try:
            from weall.runtime import executor as executor_mod
        except Exception:
            return cls.defaults()

        return cls(
            schedule_account_recovery_system_txs=getattr(
                executor_mod,
                "schedule_account_recovery_system_txs",
                schedule_account_recovery_system_txs,
            ),
            schedule_poh_async_system_txs=getattr(
                executor_mod, "schedule_poh_async_system_txs", schedule_poh_async_system_txs
            ),
            schedule_poh_tier2_system_txs=getattr(
                executor_mod, "schedule_poh_tier2_system_txs", schedule_poh_tier2_system_txs
            ),
            schedule_poh_live_system_txs=getattr(
                executor_mod, "schedule_poh_live_system_txs", schedule_poh_live_system_txs
            ),
            schedule_node_operator_system_txs=getattr(
                executor_mod, "schedule_node_operator_system_txs", schedule_node_operator_system_txs
            ),
            schedule_reputation_accrual_system_txs=getattr(
                executor_mod,
                "schedule_reputation_accrual_system_txs",
                schedule_reputation_accrual_system_txs,
            ),
            tick_governance_lifecycle=getattr(
                executor_mod, "tick_governance_lifecycle", tick_governance_lifecycle
            ),
            tick_dispute_lifecycle=getattr(
                executor_mod, "tick_dispute_lifecycle", tick_dispute_lifecycle
            ),
            system_tx_emitter=getattr(executor_mod, "system_tx_emitter", system_tx_emitter),
            prune_emitted_system_queue=getattr(
                executor_mod, "prune_emitted_system_queue", prune_emitted_system_queue
            ),
        )


def _included_tx_apply(target: Callable[..., Any]) -> Callable[..., Any]:
    """Bind canonical block inclusion to one-shot nonce semantics.

    Leader construction and follower replay both use ``RuntimeContext``.  Once a
    non-SYSTEM transaction is admitted into a canonical block, even an execution
    failure is itself a canonical included outcome with a receipt.  Consuming the
    envelope nonce on that failure makes the exact signed identity one-shot and
    closes the cross-block replay window without changing direct/local apply
    helpers, which still retain their historical non-consuming failure semantics.

    The public executor symbol is wrapped rather than bypassed so tests that
    monkeypatch ``weall.runtime.executor.apply_tx_atomic_meta`` continue to
    exercise the same inclusion boundary.
    """

    def _apply(state: Any, env: Any, *, consume_nonce_on_fail: bool = False) -> Any:
        del consume_nonce_on_fail
        return target(state, env, consume_nonce_on_fail=True)

    return _apply


@dataclass(frozen=True)
class TxExecutionSet:
    """Tx execution callables used by leader construction and replay.

    Block inclusion is intentionally stricter than direct/local apply: an
    included user transaction consumes its nonce even when domain execution
    fails and emits a failed receipt.  This prevents the same canonical signed
    transaction from being included again in a later block.
    """

    apply_tx_atomic_meta: Callable[..., Any] = _included_tx_apply(apply_tx_atomic_meta)

    @classmethod
    def defaults(cls) -> TxExecutionSet:
        return cls()

    @classmethod
    def from_executor_module(cls) -> TxExecutionSet:
        try:
            from weall.runtime import executor as executor_mod
        except Exception:
            return cls.defaults()
        target = getattr(executor_mod, "apply_tx_atomic_meta", apply_tx_atomic_meta)
        return cls(apply_tx_atomic_meta=_included_tx_apply(target))


@dataclass(frozen=True)
class RuntimeContext:
    """Minimal explicit context for extracted executor delegates."""

    executor: Any
    scheduler_set: SchedulerSet
    tx_execution_set: TxExecutionSet

    @classmethod
    def from_executor(cls, executor: Any) -> RuntimeContext:
        return cls(
            executor=executor,
            scheduler_set=SchedulerSet.from_executor_module(),
            tx_execution_set=TxExecutionSet.from_executor_module(),
        )
