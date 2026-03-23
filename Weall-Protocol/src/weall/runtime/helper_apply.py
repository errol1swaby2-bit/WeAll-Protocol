from typing import Dict, Any, List
from weall.runtime.helper_merge import (
    detect_overlap,
    apply_lane_deltas,
)


def apply_helper_results_if_safe(
    base_state: Dict[str, Any],
    lane_results: List[Dict[str, Any]],
) -> Dict[str, Any]:
    """
    Applies helper lane deltas ONLY if safe.

    Fail-closed:
    - overlap → fallback (return original state)
    - invalid structure → fallback
    """

    if not lane_results:
        return base_state

    # Extract write sets
    write_sets = [lane.get("writes", {}) for lane in lane_results]

    # --- Overlap detection ---
    if detect_overlap(write_sets):
        return base_state  # fallback

    # --- Apply deterministic merge ---
    new_state = apply_lane_deltas(base_state, lane_results)

    return new_state
