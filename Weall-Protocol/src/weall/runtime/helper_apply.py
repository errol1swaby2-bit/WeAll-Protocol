from __future__ import annotations

import copy
from collections.abc import Mapping, Sequence
from typing import Any

from weall.runtime.helper_certificates import HelperExecutionCertificate
from weall.runtime.helper_merge import (
    MaterializedLaneResult,
    merge_materialized_lane_results,
)
from weall.runtime.parallel_execution import LanePlan

Json = dict[str, Any]


def apply_helper_results_if_safe(
    base_state: Json,
    lane_results: Sequence[MaterializedLaneResult],
    *,
    lane_plans: Sequence[LanePlan],
    accepted_certificates: Mapping[str, HelperExecutionCertificate | Mapping[str, Any]],
) -> Json:
    """Apply authenticated, locally authorized helper results or fail closed.

    The caller must provide coordinator-local lane plans and certificates already
    accepted by authenticated helper dispatch.  Any malformed, missing, unknown,
    duplicate, or serialized lane causes whole-plan fallback because this wrapper
    has no transaction executor with which to replay rejected lanes.
    """

    results = list(lane_results or ())
    if not results:
        return copy.deepcopy(base_state)
    if any(not isinstance(item, MaterializedLaneResult) for item in results):
        return copy.deepcopy(base_state)

    outcome = merge_materialized_lane_results(
        base_state=base_state,
        lane_results=results,
        lane_plans=tuple(lane_plans or ()),
        accepted_certificates=dict(accepted_certificates or {}),
    )
    if outcome.serialized_lane_ids:
        return copy.deepcopy(base_state)
    return outcome.merged_state


__all__ = ["apply_helper_results_if_safe"]
