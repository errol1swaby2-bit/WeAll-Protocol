from __future__ import annotations

from typing import Any

from weall.runtime.system_tx_engine import enqueue_system_tx

Json = dict[str, Any]


def _as_str(v: Any) -> str:
    try:
        return str(v).strip()
    except Exception:
        return ""


def _as_int(v: Any, default: int = 0) -> int:
    try:
        return int(v)
    except Exception:
        return int(default)


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


def _accounts_root(state: Json) -> Json:
    accounts = state.get("accounts")
    return accounts if isinstance(accounts, dict) else {}


def _account_record(state: Json, account_id: str) -> Json:
    rec = _accounts_root(state).get(account_id)
    return rec if isinstance(rec, dict) else {}


def _active_node_pubkeys_for_account(account: Json) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    devices = account.get("devices")
    by_id = devices.get("by_id") if isinstance(devices, dict) else None
    if not isinstance(by_id, dict):
        return out
    for rec_any in by_id.values():
        rec = _as_dict(rec_any)
        if bool(rec.get("revoked", False)):
            continue
        if _as_str(rec.get("device_type") or "").lower() != "node":
            continue
        pubkey = _as_str(rec.get("pubkey") or "")
        if pubkey and pubkey not in seen:
            seen.add(pubkey)
            out.append(pubkey)
    return sorted(out)


def _node_key_owner_map(state: Json) -> dict[str, str]:
    owners: dict[str, str] = {}
    for account_id_raw, account_any in _accounts_root(state).items():
        account_id = _as_str(account_id_raw)
        if not account_id:
            continue
        for pubkey in _active_node_pubkeys_for_account(_as_dict(account_any)):
            owners.setdefault(pubkey, account_id)
    return owners


def _has_unique_node_key(state: Json, account_id: str) -> bool:
    account = _account_record(state, account_id)
    node_keys = _active_node_pubkeys_for_account(account)
    if not node_keys:
        return False
    owners = _node_key_owner_map(state)
    for pubkey in node_keys:
        if owners.get(pubkey) == account_id:
            return True
    return False


def _account_is_baseline_operator_eligible(state: Json, account_id: str) -> tuple[bool, str]:
    account = _account_record(state, account_id)
    if not account:
        return False, "account_not_found"
    if bool(account.get("banned", False)):
        return False, "account_banned"
    if bool(account.get("locked", False)):
        return False, "account_locked"
    if _as_int(account.get("poh_tier"), 0) < 2:
        return False, "poh_tier_insufficient"
    if not _has_unique_node_key(state, account_id):
        return False, "node_key_missing"
    return True, "eligible"


def schedule_node_operator_system_txs(state: Json, *, next_height: int) -> int:
    """Auto-activate baseline Node Operator status for eligible enrollments.

    This scheduler is intentionally narrow. It grants only the baseline
    NodeOperator role once deterministic prerequisites are met. Validator,
    storage, helper, and other service responsibilities remain opt-in/capacity
    or reputation gated and are not granted by this baseline activation.
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
        ok, reason = _account_is_baseline_operator_eligible(state, account_id)
        rec["activation_check"] = reason
        rec.setdefault("responsibilities", {})
        responsibilities = rec.get("responsibilities")
        if not isinstance(responsibilities, dict):
            responsibilities = {}
            rec["responsibilities"] = responsibilities
        responsibilities.setdefault("validator", {"opted_in": False, "active": False})
        responsibilities.setdefault(
            "storage",
            {"opted_in": False, "active": False, "declared_capacity_bytes": 0, "proven_capacity_bytes": 0},
        )
        by_id[account_id] = rec
        if not ok:
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
