from __future__ import annotations

from typing import Any

from weall.runtime.node_operator_responsibilities import VALIDATOR_REPUTATION_REQUIRED_MILLI

from weall.runtime.node_operator_responsibilities import (
    evaluate_baseline_node_operator,
    first_blocking_reason,
)
from weall.runtime.system_tx_engine import enqueue_system_tx

Json = dict[str, Any]


def _as_dict(v: Any) -> Json:
    return v if isinstance(v, dict) else {}


def _roles_root(state: Json) -> Json:
    roles = state.get("roles")
    if not isinstance(roles, dict):
        roles = {}
        state["roles"] = roles
    ops = roles.get("node_operators")
    if not isinstance(ops, dict):
        ops = {"by_id": {}, "active_set": []}
        roles["node_operators"] = ops
    if not isinstance(ops.get("by_id"), dict):
        ops["by_id"] = {}
    if not isinstance(ops.get("active_set"), list):
        ops["active_set"] = []
    return roles


def _ensure_responsibility_defaults(rec: Json) -> None:
    responsibilities = rec.get("responsibilities")
    if not isinstance(responsibilities, dict):
        responsibilities = {}
        rec["responsibilities"] = responsibilities
    responsibilities.setdefault(
        "validator",
        {"opted_in": False, "active": False, "readiness_status": "not_requested", "reputation_required_milli": VALIDATOR_REPUTATION_REQUIRED_MILLI},
    )
    responsibilities.setdefault(
        "storage",
        {
            "opted_in": False,
            "active": False,
            "declared_capacity_bytes": 0,
            "proven_capacity_bytes": 0,
            "allocated_capacity_bytes": 0,
            "proof_status": "not_requested",
        },
    )


def schedule_node_operator_system_txs(state: Json, *, next_height: int) -> int:
    """Auto-activate baseline Node Operator status for eligible enrollments.

    The shared responsibility evaluator is the single source of truth for the
    baseline activation prerequisites. This scheduler grants only baseline
    NodeOperator status; validator/storage responsibilities remain separate.
    """

    roles = _roles_root(state)
    ops = roles.get("node_operators") if isinstance(roles.get("node_operators"), dict) else {}
    by_id = ops.get("by_id") if isinstance(ops, dict) else {}
    active_set_raw = ops.get("active_set") if isinstance(ops, dict) else []
    active_set = {str(v).strip() for v in active_set_raw if str(v).strip()} if isinstance(active_set_raw, list) else set()
    if not isinstance(by_id, dict):
        return 0

    enq = 0
    for account_id in sorted(str(k).strip() for k in by_id.keys() if str(k).strip()):
        if account_id in active_set:
            continue
        rec = _as_dict(by_id.get(account_id))
        if not bool(rec.get("enrolled", False)):
            continue
        if bool(rec.get("suspended", False)):
            continue
        _ensure_responsibility_defaults(rec)
        evaluation = evaluate_baseline_node_operator(state, account_id)
        rec["activation_check"] = "eligible" if evaluation.eligible else first_blocking_reason(evaluation)
        rec["responsibility_status"] = {"baseline": evaluation.as_dict()}
        by_id[account_id] = rec
        if not evaluation.eligible:
            continue
        enqueue_system_tx(
            state,
            tx_type="ROLE_NODE_OPERATOR_ACTIVATE",
            payload={"account_id": account_id},
            due_height=int(next_height),
            signer="SYSTEM",
            once=True,
            parent=None,
            phase="post",
        )
        enq += 1
    return enq
