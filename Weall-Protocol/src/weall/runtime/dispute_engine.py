from __future__ import annotations

"""Deterministic dispute appeal-window scheduler."""

from typing import Any

from weall.runtime.constitutional_clock import policy_from_state
from weall.runtime.system_tx_engine import enqueue_system_tx

Json = dict[str, Any]


def _i(v: Any, default: int = 0) -> int:
    try:
        return int(v)
    except Exception:
        return int(default)


def _d(v: Any) -> dict[str, Any]:
    return v if isinstance(v, dict) else {}


def _appeal_window_blocks(dispute: Json, *, default: int = 72) -> int:
    rules = _d(dispute.get("rules"))
    return max(1, _i(dispute.get("appeal_window_blocks", rules.get("appeal_window_blocks", default)), default))


def tick_dispute_lifecycle(state: Json, *, next_height: int) -> int:
    policy = policy_from_state(state)
    if not policy.enabled:
        return 0
    disputes = state.get("disputes_by_id")
    if not isinstance(disputes, dict) or not disputes:
        return 0
    enq = 0
    for did, dispute in list(disputes.items()):
        if not isinstance(dispute, dict):
            continue
        stage = str(dispute.get("stage") or "").strip().lower()
        if stage not in {"appeal_window", "appealed", "appeal_review", "appeal_resolved"}:
            continue
        deadline = _i(dispute.get("appeal_deadline_height"), 0)
        if deadline <= 0:
            verdict_h = _i(dispute.get("verdict_at_height") or dispute.get("resolved_at_height"), next_height)
            deadline = int(verdict_h) + _appeal_window_blocks(dispute)
            dispute["appeal_deadline_height"] = int(deadline)
        if stage in {"appealed", "appeal_review"}:
            continue
        if int(next_height) >= int(deadline) + 1:
            parent_ref = f"dispute:{did}:appeal-finalize:{int(next_height)}"
            enqueue_system_tx(
                state,
                tx_type="DISPUTE_FINAL_RECEIPT",
                payload={
                    "dispute_id": str(did),
                    "resolution": dispute.get("resolution") or {},
                    "appeal_window_closed": True,
                    "appeal_deadline_height": int(deadline),
                    "_parent_ref": parent_ref,
                },
                due_height=int(next_height),
                signer="SYSTEM",
                once=True,
                parent=parent_ref,
                phase="pre",
            )
            dispute["stage"] = "finalizing"
            enq += 1
    return enq
