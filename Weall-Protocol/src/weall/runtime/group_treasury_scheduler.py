# src/weall/runtime/group_treasury_scheduler.py
from __future__ import annotations

import hashlib
import json
from typing import Any

from weall.runtime.ballot_policy import strict_civic_governance_enabled
from weall.runtime.econ_phase import econ_allowed_from_state
from weall.runtime.system_tx_engine import enqueue_system_tx

Json = dict[str, Any]


def _as_int(v: Any, default: int = 0) -> int:
    try:
        return int(v)
    except Exception:
        return int(default)


def _as_str(v: Any) -> str:
    try:
        return str(v).strip()
    except Exception:
        return ""


def _param_int(state: Json, key: str, default: int = 0) -> int:
    params = state.get("params")
    if isinstance(params, dict):
        v = params.get(key)
        try:
            return int(v)
        except Exception:
            return int(default)
    return int(default)


def _height_now(state: Json) -> int:
    # Apply-time convention: normal txs apply at height+1.
    return _as_int(state.get("height"), 0) + 1


def _allowed_signers(spend: Json) -> set[str]:
    allowed = spend.get("allowed_signers")
    if isinstance(allowed, list):
        return {str(x).strip() for x in allowed if isinstance(x, str) and x.strip()}
    return set()


def _valid_sigs(spend: Json) -> set[str]:
    sigs = spend.get("signatures")
    if not isinstance(sigs, dict):
        return set()
    signed_by = {str(k).strip() for k in sigs.keys() if isinstance(k, str) and str(k).strip()}
    allowed = _allowed_signers(spend)
    if allowed:
        return {s for s in signed_by if s in allowed}
    return signed_by


def _is_terminal(spend: Json) -> bool:
    st = _as_str(spend.get("status")).lower()
    return st in {"executed", "canceled", "cancelled", "expired"}


def _economic_policy_declared(state: Json) -> bool:
    """True when state explicitly opts into the Genesis economics posture.

    Old isolated scheduler fixtures predate the economics state contract and do
    not carry params at all. Production/strict chains are always gated; legacy
    fixtures remain compatible unless they explicitly declare economic policy.
    """

    params = state.get("params")
    if not isinstance(params, dict):
        return False
    return any(
        key in params
        for key in (
            "economics_enabled",
            "economic_unlock_time",
            "genesis_time",
        )
    )


def group_spend_plan_view(spend: Json) -> Json:
    """Return the immutable political spend terms approved by governance.

    Signer snapshots and collected signatures are execution-authority data, not
    policy terms. The commitment therefore binds the spend identity, political
    scope, treasury, recipient, value, and timing that governance authorizes.
    """

    return {
        "spend_id": _as_str(spend.get("spend_id")),
        "group_id": _as_str(spend.get("group_id")),
        "treasury_id": _as_str(spend.get("treasury_id")),
        "to": _as_str(spend.get("to")),
        "amount": _as_int(spend.get("amount"), 0),
        "created_at_height": _as_int(spend.get("created_at_height"), 0),
        "earliest_execute_height": _as_int(spend.get("earliest_execute_height"), 0),
    }


def group_spend_plan_hash(spend: Json) -> str:
    payload = json.dumps(
        group_spend_plan_view(spend),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def _strict_governance_approval(spend: Json) -> Json | None:
    approval = spend.get("governance_approval")
    if not isinstance(approval, dict):
        return None
    proposal_id = _as_str(approval.get("proposal_id"))
    approved_hash = _as_str(approval.get("spend_plan_hash"))
    if not proposal_id or not approved_hash:
        return None
    if approved_hash != group_spend_plan_hash(spend):
        return None
    return approval


def maybe_enqueue_group_spend_execute(state: Json, *, spend: Json) -> str | None:
    """Enqueue a threshold-signed group spend when all authority layers exist.

    Canon (tx_canon.yaml):
      - origin SYSTEM, receipt_only
      - parent required: GROUP_TREASURY_SPEND_SIGN
      - via_gov_execute: true

    In strict civic governance, multisig proves execution authority only. A
    matching governance approval commitment must already bind the immutable
    spend plan before threshold signatures can cause value execution. Either
    ordering is supported safely: governance may approve before or after the
    threshold is reached; repeated scheduler calls are deterministic and deduped.
    """
    if not isinstance(spend, dict):
        return None
    if _is_terminal(spend):
        return None

    strict = strict_civic_governance_enabled(state)

    # Production/strict chains and any state that explicitly declares Genesis
    # economics fail closed while value movement is locked or disabled. Legacy
    # unit fixtures with no economic policy declaration retain compatibility.
    if (strict or _economic_policy_declared(state)) and not econ_allowed_from_state(state):
        return None

    spend_id = _as_str(spend.get("spend_id"))
    if not spend_id:
        return None

    approval: Json | None = None
    if strict:
        approval = _strict_governance_approval(spend)
        if approval is None:
            return None

    threshold = _as_int(spend.get("threshold"), 0)
    if threshold <= 0:
        threshold = 1

    valid = _valid_sigs(spend)
    if len(valid) < int(threshold):
        return None

    current_apply_height = _height_now(state)
    due_h = _as_int(spend.get("earliest_execute_height"), 0)
    if due_h <= 0:
        due_h = current_apply_height
    else:
        # Reaching multisig threshold after the timelock must not enqueue work
        # at a historical height that the exact-height SYSTEM emitter can never
        # select. Execute at the current applying block once the timelock is
        # already satisfied.
        due_h = max(int(due_h), int(current_apply_height))

    payload: Json = {
        "spend_id": spend_id,
        "_parent_ref": "GROUP_TREASURY_SPEND_SIGN",
    }
    if approval is not None:
        # Internal queue metadata binds the emitted value movement to the exact
        # governance-approved plan. These underscore-prefixed fields are not
        # user-controlled canon payload fields.
        payload["_governance_proposal_id"] = _as_str(approval.get("proposal_id"))
        payload["_approved_spend_plan_hash"] = _as_str(approval.get("spend_plan_hash"))

    return enqueue_system_tx(
        state,
        tx_type="GROUP_TREASURY_SPEND_EXECUTE",
        payload=payload,
        due_height=int(due_h),
        signer="SYSTEM",
        once=True,
        parent="GROUP_TREASURY_SPEND_SIGN",
        phase="post",
    )


def maybe_enqueue_group_spend_expire(state: Json, *, spend: Json) -> str | None:
    """Enqueue GROUP_TREASURY_SPEND_EXPIRE if expiry policy is enabled.

    Policy:
      - state.params.group_treasury_spend_expiry_blocks (int)
      - if <= 0, do not enqueue.

    Canon parent required: GROUP_TREASURY_SPEND_PROPOSE.
    """
    if not isinstance(spend, dict):
        return None
    if _is_terminal(spend):
        return None

    spend_id = _as_str(spend.get("spend_id"))
    group_id = _as_str(spend.get("group_id"))
    if not spend_id or not group_id:
        return None

    expiry_blocks = _param_int(state, "group_treasury_spend_expiry_blocks", 0)
    if int(expiry_blocks) <= 0:
        return None

    created_h = _as_int(spend.get("created_at_height"), 0)
    if created_h <= 0:
        created_h = _height_now(state)

    due_h = int(created_h) + int(expiry_blocks)
    if due_h <= 0:
        return None

    payload = {
        "group_id": group_id,
        "spend_id": spend_id,
        "_parent_ref": "GROUP_TREASURY_SPEND_PROPOSE",
    }
    return enqueue_system_tx(
        state,
        tx_type="GROUP_TREASURY_SPEND_EXPIRE",
        payload=payload,
        due_height=int(due_h),
        signer="SYSTEM",
        once=True,
        parent="GROUP_TREASURY_SPEND_PROPOSE",
        phase="post",
    )


__all__ = [
    "group_spend_plan_hash",
    "group_spend_plan_view",
    "maybe_enqueue_group_spend_execute",
    "maybe_enqueue_group_spend_expire",
]
