from __future__ import annotations

from dataclasses import dataclass, replace
from typing import Any, Mapping, Sequence

from weall.runtime.helper_assembly_gate import (
    HelperAssemblyProfile,
    decide_helper_block_assembly,
)
from weall.runtime.helper_dispatch import HelperDispatchContext
from weall.runtime.helper_event_driver import HelperEvent
from weall.runtime.helper_lane_journal import HelperLaneJournal
from weall.runtime.helper_proposal_orchestrator import HelperProposalOrchestrator
from weall.runtime.helper_replay_guard import HelperReplayGuard
from weall.runtime.parallel_execution import LanePlan, canonical_lane_plan_fingerprint


Json = dict[str, Any]


@dataclass(frozen=True, slots=True)
class HelperProposalCycleInput:
    block_height: int
    events: tuple[HelperEvent, ...]
    lane_results_by_id: Mapping[str, Mapping[str, Any]]
    require_serial_equivalence: bool = True
    fail_closed_on_helper_error: bool = True


@dataclass(frozen=True, slots=True)
class HelperProposalCycleResult:
    block_height: int
    resolved_lanes: tuple[str, ...]
    finalized_modes: tuple[tuple[str, str], ...]
    event_codes: tuple[str, ...]
    assembly_mode: str
    assembly_code: str
    assembly_accepted: bool
    plan_id: str = ""

    def to_json(self) -> Json:
        return {
            "block_height": self.block_height,
            "resolved_lanes": list(self.resolved_lanes),
            "finalized_modes": [[lane_id, mode] for lane_id, mode in self.finalized_modes],
            "event_codes": list(self.event_codes),
            "assembly_mode": self.assembly_mode,
            "assembly_code": self.assembly_code,
            "assembly_accepted": self.assembly_accepted,
            "plan_id": self.plan_id,
        }


@dataclass(frozen=True, slots=True)
class HelperProposalLoopSummary:
    cycle_count: int
    results: tuple[HelperProposalCycleResult, ...]

    def accepted_heights(self) -> tuple[int, ...]:
        return tuple(result.block_height for result in self.results if result.assembly_accepted)

    def helper_assisted_heights(self) -> tuple[int, ...]:
        return tuple(
            result.block_height for result in self.results if result.assembly_mode == "helper_assisted"
        )

    def plan_ids(self) -> tuple[str, ...]:
        return tuple(str(result.plan_id or "") for result in self.results)


def run_helper_proposal_cycle(
    *,
    context: HelperDispatchContext,
    lane_plans: Sequence[LanePlan],
    cycle: HelperProposalCycleInput,
    helper_pubkeys: Mapping[str, str] | None = None,
    journal: HelperLaneJournal | None = None,
    helper_timeout_ms: int = 5000,
    serial_equivalence_fn=None,
) -> HelperProposalCycleResult:
    """
    Run one proposer-style helper cycle using the repo-native integrated helper path.

    This intentionally reuses:
    - HelperProposalOrchestrator
    - HelperReplayGuard
    - HelperAssemblyGate

    The goal is not to replace block production, but to prove the helper path stays
    deterministic when exercised as repeated proposer-local cycles.
    """
    computed_plan_id = str(context.plan_id or canonical_lane_plan_fingerprint(tuple(lane_plans or ())))
    if computed_plan_id and computed_plan_id != str(context.plan_id or ""):
        context = replace(context, plan_id=computed_plan_id)

    orchestrator = HelperProposalOrchestrator(
        context=context,
        lane_plans=tuple(lane_plans),
        helper_pubkeys=dict(helper_pubkeys or {}),
        journal=journal,
        helper_timeout_ms=helper_timeout_ms,
    )
    guard = HelperReplayGuard(
        orchestrator=orchestrator,
        journal=journal,
    )

    codes: list[str] = []
    for event in cycle.events:
        kind = str(event.kind or "")
        if kind == "start":
            orchestrator.start_collection(started_ms=int(event.started_ms))
            codes.append("start")
        elif kind == "cert":
            if event.cert is None:
                codes.append("missing_cert")
                continue
            outcome = guard.ingest_certificate(
                cert=event.cert,
                peer_id=str(event.peer_id or ""),
            )
            codes.append(str(outcome.code))
        elif kind == "timeout":
            outcomes = guard.finalize_timeouts(now_ms=int(event.now_ms))
            if not outcomes:
                codes.append("timeout_noop")
            else:
                for outcome in outcomes:
                    codes.append(str(outcome.code))
        else:
            codes.append("unknown_event")

    profile = HelperAssemblyProfile(
        helper_mode_enabled=True,
        require_serial_equivalence=bool(cycle.require_serial_equivalence),
        fail_closed_on_helper_error=bool(cycle.fail_closed_on_helper_error),
    )
    decision = decide_helper_block_assembly(
        profile=profile,
        resolutions=orchestrator.finalized_resolutions(),
        lane_results_by_id=cycle.lane_results_by_id,
        serial_equivalence_fn=serial_equivalence_fn,
    )

    finalized_modes = tuple(
        (str(item.lane_id), str(item.mode))
        for item in orchestrator.finalized_resolutions()
    )
    return HelperProposalCycleResult(
        block_height=int(cycle.block_height),
        resolved_lanes=guard.resolved_lanes(),
        finalized_modes=finalized_modes,
        event_codes=tuple(codes),
        assembly_mode=str(decision.mode),
        assembly_code=str(decision.code),
        assembly_accepted=bool(decision.accepted),
        plan_id=computed_plan_id,
    )


def run_helper_proposal_loop(
    *,
    base_context: HelperDispatchContext,
    lane_plans: Sequence[LanePlan],
    cycles: Sequence[HelperProposalCycleInput],
    helper_pubkeys: Mapping[str, str] | None = None,
    journal_factory=None,
    helper_timeout_ms: int = 5000,
    serial_equivalence_fn=None,
) -> HelperProposalLoopSummary:
    """
    Run repeated proposer-style helper cycles in isolation.

    Each cycle gets its own journal unless journal_factory intentionally reuses one.
    This lets tests cover both:
    - independent proposer cycles
    - restart / replay continuity across cycles
    """
    results: list[HelperProposalCycleResult] = []
    computed_plan_id = str(base_context.plan_id or canonical_lane_plan_fingerprint(tuple(lane_plans or ())))

    for idx, cycle in enumerate(cycles):
        journal = journal_factory(idx) if journal_factory is not None else None
        context = HelperDispatchContext(
            chain_id=str(base_context.chain_id),
            block_height=int(cycle.block_height),
            view=int(base_context.view),
            leader_id=str(base_context.leader_id),
            validator_epoch=int(base_context.validator_epoch),
            validator_set_hash=str(base_context.validator_set_hash),
            manifest_hash=str(base_context.manifest_hash),
            coordinator_pubkey=str(base_context.coordinator_pubkey),
            manifest_signature=str(base_context.manifest_signature),
            manifest_signed=bool(base_context.manifest_signed),
            manifest_signature_required=bool(base_context.manifest_signature_required),
            manifest_payload=base_context.manifest_payload,
            strict_helper_certificate_consistency=bool(
                base_context.strict_helper_certificate_consistency
            ),
            strict_helper_receipts_root=bool(base_context.strict_helper_receipts_root),
            strict_helper_state_delta_hash=bool(base_context.strict_helper_state_delta_hash),
            plan_id=computed_plan_id,
        )
        results.append(
            run_helper_proposal_cycle(
                context=context,
                lane_plans=lane_plans,
                cycle=cycle,
                helper_pubkeys=helper_pubkeys,
                journal=journal,
                helper_timeout_ms=helper_timeout_ms,
                serial_equivalence_fn=serial_equivalence_fn,
            )
        )

    return HelperProposalLoopSummary(
        cycle_count=len(results),
        results=tuple(results),
    )
