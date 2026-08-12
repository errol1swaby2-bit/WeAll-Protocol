from __future__ import annotations

import copy
from collections.abc import Sequence
from typing import Any

from weall.runtime.helper_merge import (
    MaterializedLaneResult,
    merge_materialized_lane_results,
)

Json = dict[str, Any]


def apply_helper_results_if_safe(
    base_state: Json,
    lane_results: Sequence[MaterializedLaneResult],
) -> Json:
    """Apply verified materialized helper results or fail closed to ``base_state``.

    This wrapper intentionally delegates verification, overlap detection, canonical
    delta ordering, and merge semantics to the single canonical helper-merge path.
    Any malformed or serialized lane causes whole-plan fallback because this helper
    has no transaction executor with which to safely replay rejected lanes.
    """

    results = list(lane_results or ())
    if not results:
        return copy.deepcopy(base_state)
    if any(not isinstance(item, MaterializedLaneResult) for item in results):
        return copy.deepcopy(base_state)

    outcome = merge_materialized_lane_results(
        base_state=base_state,
        lane_results=results,
    )
    if outcome.serialized_lane_ids:
        return copy.deepcopy(base_state)
    return outcome.merged_state


__all__ = ["apply_helper_results_if_safe"]
