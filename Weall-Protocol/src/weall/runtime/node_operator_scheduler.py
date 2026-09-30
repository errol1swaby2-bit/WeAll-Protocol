from __future__ import annotations

from typing import Any

from weall.runtime.node_operator_responsibilities import (
    evaluate_baseline_node_operator,
    evaluate_validator_responsibility,
    first_blocking_reason,
)
from weall.runtime.system_tx_engine import enqueue_system_tx
from weall.runtime.validator_readiness_runner import (
    ValidatorReadinessError,
    validate_validator_readiness_payload,
)

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
        {
            "opted_in": False,
            "active": False,
            "readiness_status": "not_requested",
            "reputation_required_milli": 5000,
        },
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
    active_set = (
        {str(v).strip() for v in active_set_raw if str(v).strip()}
        if isinstance(active_set_raw, list)
        else set()
    )
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
        rec["activation_check"] = (
            "eligible" if evaluation.eligible else first_blocking_reason(evaluation)
        )
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

    validators = roles.get("validators")
    if not isinstance(validators, dict):
        validators = {"by_id": {}, "active_set": []}
        roles["validators"] = validators
    validator_active_raw = validators.get("active_set")
    validator_active = (
        {str(value).strip() for value in validator_active_raw if str(value).strip()}
        if isinstance(validator_active_raw, list)
        else set()
    )

    for account_id in sorted(str(k).strip() for k in by_id.keys() if str(k).strip()):
        operator = _as_dict(by_id.get(account_id))
        responsibilities = _as_dict(operator.get("responsibilities"))
        validator = _as_dict(responsibilities.get("validator"))
        if not bool(validator.get("opted_in", False)):
            continue

        node_pubkey = str(validator.get("node_pubkey") or "").strip()
        evaluation = evaluate_validator_responsibility(state, account_id, node_pubkey=node_pubkey)
        readiness_status = str(validator.get("readiness_status") or "").strip().lower()

        if not bool(validator.get("active", False)) or readiness_status not in {
            "ready",
            "verified",
            "active",
        }:
            blockers = set(evaluation.reasons) - {"validator_readiness_pending"}
            if blockers:
                continue
            payload = {
                "account_id": account_id,
                "verification_status": "verified",
                "node_pubkey": node_pubkey,
                "bft_pubkey": str(validator.get("bft_pubkey") or "").strip(),
                "chain_id": str(validator.get("chain_id") or "").strip(),
                "schema_version": str(validator.get("schema_version") or "").strip(),
                "protocol_version": str(validator.get("protocol_version") or "").strip(),
                "manifest_hash": str(validator.get("manifest_hash") or "").strip(),
                "tx_index_hash": str(validator.get("tx_index_hash") or "").strip(),
                "runtime_profile_hash": str(validator.get("runtime_profile_hash") or "").strip(),
                "readiness_expires_height": int(validator.get("readiness_expires_height") or 0),
                "readiness_checks": dict(_as_dict(validator.get("readiness_checks"))),
                "readiness_receipt_hash": str(
                    validator.get("readiness_receipt_hash") or ""
                ).strip(),
            }
            try:
                validate_validator_readiness_payload(
                    payload,
                    account_id=account_id,
                    expected_node_pubkey=node_pubkey,
                    current_height=int(state.get("height") or 0),
                )
            except (ValidatorReadinessError, TypeError, ValueError):
                continue
            enqueue_system_tx(
                state,
                tx_type="VALIDATOR_READINESS_VERIFY",
                payload=payload,
                due_height=int(next_height),
                signer="SYSTEM",
                once=True,
                parent=None,
                phase="post",
            )
            enq += 1
            continue

        if account_id in validator_active or not evaluation.active:
            continue
        enqueue_system_tx(
            state,
            tx_type="ROLE_VALIDATOR_ACTIVATE",
            payload={"account_id": account_id, "node_pubkey": node_pubkey},
            due_height=int(next_height),
            signer="SYSTEM",
            once=True,
            parent=None,
            phase="post",
        )
        enq += 1

    return enq
