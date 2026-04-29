from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, Mapping, Sequence

from weall.runtime.helper_merge_admission import (
    HelperMergeAdmissionDecision,
    admit_helper_merge,
)
from weall.runtime.helper_proposal_orchestrator import HelperLaneResolution


Json = dict[str, Any]


@dataclass(frozen=True, slots=True)
class HelperAssemblyProfile:
    helper_mode_enabled: bool = False
    require_serial_equivalence: bool = True
    fail_closed_on_helper_error: bool = True


@dataclass(frozen=True, slots=True)
class HelperAssemblyDecision:
    mode: str  # "serial_only" | "helper_assisted"
    accepted: bool
    code: str
    merge_decision: HelperMergeAdmissionDecision | None = None


def decide_helper_block_assembly(
    *,
    profile: HelperAssemblyProfile,
    resolutions: Sequence[HelperLaneResolution],
    lane_results_by_id: Mapping[str, Mapping[str, Any]],
    serial_equivalence_fn: Callable[[tuple[Any, ...]], bool] | None = None,
) -> HelperAssemblyDecision:
    """
    Final proposer-local gate before helper-assisted block assembly is allowed.

    Safety posture:
    - if helper mode is disabled, always return serial_only
    - if helper mode is enabled, helper-assisted assembly is allowed only when
      merge admission accepts
    - if helper mode is enabled and fail_closed_on_helper_error is false,
      helper failures degrade to serial_only instead of blocking assembly
    """
    if not bool(profile.helper_mode_enabled):
        return HelperAssemblyDecision(
            mode="serial_only",
            accepted=True,
            code="helper_mode_disabled",
            merge_decision=None,
        )

    merge_decision = admit_helper_merge(
        resolutions=resolutions,
        lane_results_by_id=lane_results_by_id,
        serial_equivalence_fn=serial_equivalence_fn if profile.require_serial_equivalence else None,
    )
    if merge_decision.accepted:
        return HelperAssemblyDecision(
            mode="helper_assisted",
            accepted=True,
            code="accepted",
            merge_decision=merge_decision,
        )

    if bool(profile.fail_closed_on_helper_error):
        return HelperAssemblyDecision(
            mode="helper_assisted",
            accepted=False,
            code=merge_decision.code,
            merge_decision=merge_decision,
        )

    return HelperAssemblyDecision(
        mode="serial_only",
        accepted=True,
        code=f"serial_fallback:{merge_decision.code}",
        merge_decision=merge_decision,
    )
