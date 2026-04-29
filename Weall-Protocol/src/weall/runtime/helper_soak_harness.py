from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping, Sequence

from weall.runtime.helper_dispatch import HelperDispatchContext
from weall.runtime.helper_lane_journal import HelperLaneJournal
from weall.runtime.helper_proposal_loop import (
    HelperProposalCycleInput,
    HelperProposalLoopSummary,
    run_helper_proposal_loop,
)
from weall.runtime.parallel_execution import LanePlan


Json = dict[str, Any]


@dataclass(frozen=True, slots=True)
class HelperSoakPlan:
    rounds: int
    helper_every_n: int = 2
    timeout_every_n: int = 2
    require_serial_equivalence: bool = False
    fail_closed_on_helper_error: bool = True


@dataclass(frozen=True, slots=True)
class HelperSoakSummary:
    rounds: int
    accepted_heights: tuple[int, ...]
    helper_assisted_heights: tuple[int, ...]
    fallback_heights: tuple[int, ...]
    serial_only_heights: tuple[int, ...]
    failed_heights: tuple[int, ...]
    cycle_codes: tuple[tuple[int, str], ...]

    def to_json(self) -> Json:
        return {
            "rounds": self.rounds,
            "accepted_heights": list(self.accepted_heights),
            "helper_assisted_heights": list(self.helper_assisted_heights),
            "fallback_heights": list(self.fallback_heights),
            "serial_only_heights": list(self.serial_only_heights),
            "failed_heights": list(self.failed_heights),
            "cycle_codes": [[height, code] for height, code in self.cycle_codes],
        }


def build_helper_soak_cycles(
    *,
    start_height: int,
    lane_id: str,
    helper_cert_by_height: Mapping[int, Any],
    lane_results_by_id: Mapping[str, Mapping[str, Any]],
    plan: HelperSoakPlan,
) -> tuple[HelperProposalCycleInput, ...]:
    """
    Deterministic cycle builder for long-running proposer-local helper soak tests.

    Pattern:
    - heights divisible by helper_every_n receive helper cert traffic
    - others use timeout/fallback
    """
    cycles: list[HelperProposalCycleInput] = []
    for offset in range(plan.rounds):
        height = int(start_height) + offset
        cert = helper_cert_by_height.get(height)

        if plan.helper_every_n > 0 and ((height - int(start_height)) % int(plan.helper_every_n) == 0) and cert is not None:
            events = (
                {"kind": "start", "started_ms": 1000 * (offset + 1)},
                {"kind": "cert", "cert": cert, "peer_id": str(getattr(cert, "helper_id", "") or "")},
            )
        else:
            events = (
                {"kind": "start", "started_ms": 1000 * (offset + 1)},
                {"kind": "timeout", "now_ms": 1000 * (offset + 1) + 50},
            )

        cycles.append(
            HelperProposalCycleInput(
                block_height=height,
                events=tuple(
                    __import__("weall.runtime.helper_event_driver", fromlist=["HelperEvent"]).HelperEvent(**event)
                    for event in events
                ),
                lane_results_by_id=dict(lane_results_by_id),
                require_serial_equivalence=bool(plan.require_serial_equivalence),
                fail_closed_on_helper_error=bool(plan.fail_closed_on_helper_error),
            )
        )
    return tuple(cycles)


def summarize_helper_soak(summary: HelperProposalLoopSummary) -> HelperSoakSummary:
    helper_assisted_heights: list[int] = []
    fallback_heights: list[int] = []
    serial_only_heights: list[int] = []
    failed_heights: list[int] = []
    cycle_codes: list[tuple[int, str]] = []

    for result in summary.results:
        cycle_codes.append((int(result.block_height), str(result.assembly_code)))
        if result.assembly_mode == "helper_assisted":
            helper_assisted_heights.append(int(result.block_height))
        if result.assembly_mode == "serial_only":
            serial_only_heights.append(int(result.block_height))
        if not result.assembly_accepted:
            failed_heights.append(int(result.block_height))
        if any(mode == "fallback" for _, mode in result.finalized_modes):
            fallback_heights.append(int(result.block_height))

    return HelperSoakSummary(
        rounds=summary.cycle_count,
        accepted_heights=summary.accepted_heights(),
        helper_assisted_heights=tuple(helper_assisted_heights),
        fallback_heights=tuple(fallback_heights),
        serial_only_heights=tuple(serial_only_heights),
        failed_heights=tuple(failed_heights),
        cycle_codes=tuple(cycle_codes),
    )


def run_helper_soak(
    *,
    base_context: HelperDispatchContext,
    lane_plans: Sequence[LanePlan],
    start_height: int,
    helper_cert_by_height: Mapping[int, Any],
    lane_results_by_id: Mapping[str, Mapping[str, Any]],
    plan: HelperSoakPlan,
    helper_pubkeys: Mapping[str, str] | None = None,
    journal_factory=None,
    helper_timeout_ms: int = 5000,
    serial_equivalence_fn=None,
) -> HelperSoakSummary:
    cycles = build_helper_soak_cycles(
        start_height=start_height,
        lane_id=str(next(iter(lane_results_by_id.keys()))),
        helper_cert_by_height=helper_cert_by_height,
        lane_results_by_id=lane_results_by_id,
        plan=plan,
    )
    loop_summary = run_helper_proposal_loop(
        base_context=base_context,
        lane_plans=lane_plans,
        cycles=cycles,
        helper_pubkeys=helper_pubkeys,
        journal_factory=journal_factory,
        helper_timeout_ms=helper_timeout_ms,
        serial_equivalence_fn=serial_equivalence_fn,
    )
    return summarize_helper_soak(loop_summary)
