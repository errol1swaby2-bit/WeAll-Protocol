from __future__ import annotations

from dataclasses import dataclass
from itertools import permutations
from typing import Sequence

from weall.runtime.helper_dispatch import HelperDispatchContext
from weall.runtime.helper_event_driver import (
    HelperEvent,
    HelperEventOutcomeSummary,
    run_helper_event_sequence,
)
from weall.runtime.helper_lane_journal import HelperLaneJournal
from weall.runtime.parallel_execution import LanePlan


@dataclass(frozen=True, slots=True)
class HelperStressCase:
    name: str
    events: tuple[HelperEvent, ...]


@dataclass(frozen=True, slots=True)
class HelperStressResult:
    case_name: str
    outcome_hash: str
    resolved_lanes: tuple[str, ...]
    finalized_modes: tuple[tuple[str, str], ...]
    event_codes: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class HelperStressMatrixSummary:
    result_count: int
    unique_outcome_hashes: tuple[str, ...]
    results: tuple[HelperStressResult, ...]

    def all_equivalent(self) -> bool:
        return len(self.unique_outcome_hashes) <= 1


def _result_from_summary(case_name: str, summary: HelperEventOutcomeSummary) -> HelperStressResult:
    return HelperStressResult(
        case_name=str(case_name),
        outcome_hash=str(summary.outcome_hash),
        resolved_lanes=tuple(summary.resolved_lanes),
        finalized_modes=tuple(summary.finalized_modes),
        event_codes=tuple(summary.event_codes),
    )


def run_helper_stress_cases(
    *,
    context: HelperDispatchContext,
    lane_plans: Sequence[LanePlan],
    cases: Sequence[HelperStressCase],
    helper_pubkeys: dict[str, str] | None = None,
    helper_timeout_ms: int = 5000,
    journal_factory=None,
) -> HelperStressMatrixSummary:
    """
    Deterministic stress runner for the integrated helper path.

    Each case is executed in isolation. This is a repo-native adversarial harness
    built on top of the existing event driver rather than a parallel subsystem.
    """
    results: list[HelperStressResult] = []
    hashes: set[str] = set()

    for idx, case in enumerate(cases):
        journal = journal_factory(idx) if journal_factory is not None else None
        summary = run_helper_event_sequence(
            context=context,
            lane_plans=lane_plans,
            events=case.events,
            helper_pubkeys=dict(helper_pubkeys or {}),
            journal=journal,
            helper_timeout_ms=helper_timeout_ms,
        )
        result = _result_from_summary(case.name, summary)
        results.append(result)
        hashes.add(result.outcome_hash)

    results.sort(key=lambda item: item.case_name)
    return HelperStressMatrixSummary(
        result_count=len(results),
        unique_outcome_hashes=tuple(sorted(hashes)),
        results=tuple(results),
    )


def build_equivalent_reorder_cases(
    *,
    prefix_events: Sequence[HelperEvent],
    reorderable_events: Sequence[HelperEvent],
    suffix_events: Sequence[HelperEvent],
    name_prefix: str,
) -> tuple[HelperStressCase, ...]:
    """
    Generate deterministic adversarial reorder cases.

    The caller is responsible for only using reorderable events that *should* be
    semantically equivalent under the integrated helper path. The tests then
    prove whether that assumption holds.
    """
    cases: list[HelperStressCase] = []
    for idx, perm in enumerate(permutations(tuple(reorderable_events))):
        cases.append(
            HelperStressCase(
                name=f"{name_prefix}_{idx}",
                events=tuple(prefix_events) + tuple(perm) + tuple(suffix_events),
            )
        )
    cases.sort(key=lambda item: item.name)
    return tuple(cases)
