# src/weall/runtime/group_treasury_scheduler.py
from __future__ import annotations

from typing import Any

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


def maybe_enqueue_group_spend_execute(state: Json, *, spend: Json) -> str | None:
    """If a spend has reached threshold, enqueue GROUP_TREASURY_SPEND_EXECUTE.

    Canon (tx_canon.yaml):
      - origin SYSTEM, receipt_only
      - parent required: GROUP_TREASURY_SPEND_SIGN
      - via_gov_execute: true (but may be emitted via system queue)

    Determinism:
      - enqueue_system_tx de-dupes by deterministic queue_id
      - repeated calls are safe.
    """
    if not isinstance(spend, dict):
        return None
    if _is_terminal(spend):
        return None

    spend_id = _as_str(spend.get("spend_id"))
    if not spend_id:
        return None

    threshold = _as_int(spend.get("threshold"), 0)
    if threshold <= 0:
        threshold = 1

    valid = _valid_sigs(spend)
    if len(valid) < int(threshold):
        return None

    due_h = _as_int(spend.get("earliest_execute_height"), 0)
    if due_h <= 0:
        due_h = _height_now(state)

    payload = {"spend_id": spend_id, "_parent_ref": "GROUP_TREASURY_SPEND_SIGN"}
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


__all__ = ["maybe_enqueue_group_spend_execute", "maybe_enqueue_group_spend_expire"]
