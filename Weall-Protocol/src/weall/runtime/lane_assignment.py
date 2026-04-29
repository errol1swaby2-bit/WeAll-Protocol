from __future__ import annotations

from typing import Any

from weall.runtime.execution_lanes import (
    ALL_LANES,
    LANE_PARALLEL_CONTENT,
    LANE_PARALLEL_ECONOMY,
    LANE_PARALLEL_IDENTITY,
    LANE_PARALLEL_SOCIAL,
    LANE_SERIAL,
    canonical_scope_prefixes,
    get_lane_rule,
    is_scope_ambiguous,
    requires_serial_due_to_authority,
    tx_type_of,
)

Json = dict[str, Any]

_PARALLEL_LANES: tuple[str, ...] = (
    LANE_PARALLEL_IDENTITY,
    LANE_PARALLEL_SOCIAL,
    LANE_PARALLEL_CONTENT,
    LANE_PARALLEL_ECONOMY,
)


def assign_execution_lane(tx: Json, state_snapshot_metadata: Json | None = None) -> str:
    """Return the deterministic execution lane for *tx*.

    The function is intentionally conservative:
    - any missing or ambiguous scope information => SERIAL
    - any authority-heavy or cross-domain surface => SERIAL
    - exactly one matching parallel lane => that lane
    - multiple candidate lanes => SERIAL
    """

    _ = state_snapshot_metadata  # reserved for future epoch/profile-bound rules
    tx_type = tx_type_of(tx)
    if not tx_type:
        return LANE_SERIAL
    if requires_serial_due_to_authority(tx):
        return LANE_SERIAL
    if is_scope_ambiguous(tx):
        return LANE_SERIAL

    scope = canonical_scope_prefixes(tx)
    candidates: list[str] = []
    for lane_id in _PARALLEL_LANES:
        rule = get_lane_rule(lane_id)
        if not rule.helper_allowed:
            continue
        if not rule.allows_tx_type(tx_type):
            continue
        if all(rule.allows_namespace_prefix(prefix) for prefix in scope):
            candidates.append(lane_id)

    if len(candidates) != 1:
        return LANE_SERIAL
    return str(candidates[0])


def lane_plan_for_txs(
    txs: list[Json],
    state_snapshot_metadata: Json | None = None,
) -> dict[str, list[Json]]:
    plan: dict[str, list[Json]] = {lane_id: [] for lane_id in ALL_LANES}
    for tx in list(txs or []):
        lane_id = assign_execution_lane(tx, state_snapshot_metadata)
        plan.setdefault(lane_id, []).append(tx)
    return plan
