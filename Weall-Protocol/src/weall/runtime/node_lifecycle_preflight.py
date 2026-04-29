from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Any, Mapping

from weall.runtime.reputation_units import account_reputation_units

Json = dict[str, Any]

_ALLOWED_SERVICE_ROLES = {
    "validator",
    "helper",
    "node_operator",
    "storage_operator",
    "general_service",
}


@dataclass(frozen=True, slots=True)
class ProductionPreflightResult:
    hard_fail_reasons: tuple[str, ...]
    maintenance_reasons: tuple[str, ...]
    bound_account: str
    account_exists: bool
    node_key_authorized: bool
    poh_tier_required: int
    poh_tier_actual: int
    reputation_required_milli: int
    reputation_actual_milli: int
    banned: bool
    locked: bool
    active_roles: tuple[str, ...]
    suspended_roles: tuple[str, ...]
    effective_roles: tuple[str, ...]
    helper_effective: bool
    bft_effective: bool

    @property
    def passed(self) -> bool:
        return not self.hard_fail_reasons and not self.maintenance_reasons



def _append_unique(items: list[str], *values: str) -> None:
    seen = set(items)
    for value in values:
        if value and value not in seen:
            items.append(value)
            seen.add(value)



def _node_key_candidates() -> tuple[str, ...]:
    vals = [
        str(os.environ.get("WEALL_NODE_PUBKEY") or "").strip(),
        str(os.environ.get("WEALL_NODE_PUBKEY_HEX") or "").strip(),
        str(os.environ.get("WEALL_NODE_PUBLIC_KEY") or "").strip(),
    ]
    out: list[str] = []
    seen: set[str] = set()
    for value in vals:
        if value and value not in seen:
            out.append(value)
            seen.add(value)
    return tuple(out)



def _account_record(state: Mapping[str, Any], account: str) -> Mapping[str, Any]:
    accounts = state.get("accounts")
    if not account or not isinstance(accounts, dict):
        return {}
    rec = accounts.get(account)
    return rec if isinstance(rec, dict) else {}



def _extract_active_pubkeys(acct: Mapping[str, Any]) -> tuple[str, ...]:
    out: list[str] = []
    seen: set[str] = set()

    def _add(value: Any) -> None:
        s = str(value or "").strip()
        if s and s not in seen:
            out.append(s)
            seen.add(s)

    keys = acct.get("keys")
    if isinstance(keys, dict):
        by_id = keys.get("by_id")
        if isinstance(by_id, dict):
            for rec in by_id.values():
                if not isinstance(rec, dict):
                    continue
                if bool(rec.get("revoked", False)):
                    continue
                _add(rec.get("pubkey"))
    pubkeys = acct.get("pubkeys")
    if isinstance(pubkeys, list):
        for item in pubkeys:
            _add(item)
    active_keys = acct.get("active_keys")
    if isinstance(active_keys, list):
        for item in active_keys:
            _add(item)
    primary = acct.get("pubkey")
    if primary:
        _add(primary)
    return tuple(sorted(out))



def _node_key_authorized(account_record: Mapping[str, Any], *, bound_account: str) -> bool:
    candidates = _node_key_candidates()
    if not candidates:
        return False
    active = set(_extract_active_pubkeys(account_record))
    if active:
        return any(candidate in active for candidate in candidates)
    return bool(bound_account)



def _bound_account(state: Mapping[str, Any], node_id: str) -> str:
    configured = str(
        os.environ.get("WEALL_BOUND_ACCOUNT") or os.environ.get("WEALL_VALIDATOR_ACCOUNT") or ""
    ).strip()
    if configured:
        return configured
    if node_id and node_id.startswith("@"):
        return node_id
    accounts = state.get("accounts")
    if isinstance(accounts, dict) and len(accounts) == 1:
        only = next(iter(accounts.keys()), "")
        if isinstance(only, str):
            return only
    return ""



def _required_poh_tier(requested_roles: tuple[str, ...]) -> int:
    explicit = os.environ.get("WEALL_PRODUCTION_REQUIRED_POH_TIER")
    if explicit is not None:
        try:
            return max(0, int(str(explicit).strip()))
        except Exception:
            return 0
    if "validator" in requested_roles:
        return 3
    if "helper" in requested_roles:
        return 2
    return 0



def _required_reputation_milli(requested_roles: tuple[str, ...]) -> int:
    explicit = os.environ.get("WEALL_PRODUCTION_REQUIRED_REPUTATION_MILLI")
    if explicit is not None:
        try:
            return max(0, int(str(explicit).strip()))
        except Exception:
            return 0
    if "validator" in requested_roles:
        return 5000
    if "helper" in requested_roles:
        return 2000
    if "node_operator" in requested_roles or "storage_operator" in requested_roles:
        return 1000
    return 0



def _role_bucket(roles: Mapping[str, Any], bucket: str) -> Mapping[str, Any]:
    rec = roles.get(bucket)
    return rec if isinstance(rec, dict) else {}



def _bucket_has_active(bucket: Mapping[str, Any], account: str) -> bool:
    active = bucket.get("active_set")
    if not isinstance(active, list):
        return False
    return account in {str(v).strip() for v in active if str(v).strip()}



def _bucket_has_enrolled(bucket: Mapping[str, Any], account: str) -> bool:
    by_id = bucket.get("by_id")
    if not isinstance(by_id, dict):
        return False
    rec = by_id.get(account)
    return isinstance(rec, dict) and bool(rec.get("enrolled", False))



def _role_state_lists(state: Mapping[str, Any], bound_account: str) -> tuple[tuple[str, ...], tuple[str, ...]]:
    roles = state.get("roles")
    if not isinstance(roles, dict) or not bound_account:
        return (), ()

    active_roles: list[str] = []
    suspended_roles: list[str] = []
    mapping = {
        "validator": _role_bucket(roles, "validators"),
        "node_operator": _role_bucket(roles, "node_operators"),
        "helper": _role_bucket(roles, "node_operators"),
        "storage_operator": _role_bucket(roles, "node_operators"),
        "general_service": {},
    }
    for role, bucket in mapping.items():
        if role == "general_service":
            continue
        if _bucket_has_active(bucket, bound_account):
            active_roles.append(role)
        elif _bucket_has_enrolled(bucket, bound_account):
            suspended_roles.append(role)
    return tuple(sorted(set(active_roles))), tuple(sorted(set(suspended_roles)))



def evaluate_production_preflight(
    *,
    state: Mapping[str, Any],
    node_id: str,
    chain_id: str,
    schema_version: str,
    tx_index_hash: str,
    runtime_profile_hash: str,
    requested_roles: tuple[str, ...],
    helper_requested: bool,
    bft_requested: bool,
    sigverify_required: bool,
    trusted_anchor_required: bool,
) -> ProductionPreflightResult:
    hard_fail_reasons: list[str] = []
    maintenance_reasons: list[str] = []

    bound_account = _bound_account(state, node_id)
    account_record = _account_record(state, bound_account)
    account_exists = bool(account_record)
    node_key_authorized = _node_key_authorized(account_record, bound_account=bound_account)

    if helper_requested and "helper" not in requested_roles:
        _append_unique(hard_fail_reasons, "HELPER_ROLE_NOT_REQUESTED")
    if bft_requested and "validator" not in requested_roles:
        _append_unique(hard_fail_reasons, "VALIDATOR_ROLE_NOT_REQUESTED")
    if not str(chain_id or "").strip():
        _append_unique(hard_fail_reasons, "CONFIG_MISSING_CHAIN_ID")
    if not str(schema_version or "").strip():
        _append_unique(hard_fail_reasons, "CONFIG_MISSING_SCHEMA_VERSION")
    if not str(tx_index_hash or "").strip():
        _append_unique(hard_fail_reasons, "CONFIG_MISSING_TX_INDEX_HASH")
    if not str(runtime_profile_hash or "").strip():
        _append_unique(hard_fail_reasons, "CONFIG_MISSING_RUNTIME_PROFILE_HASH")
    if not bool(sigverify_required):
        _append_unique(hard_fail_reasons, "CONFIG_SIGNATURE_VERIFY_DISABLED")
    if not bool(trusted_anchor_required):
        _append_unique(hard_fail_reasons, "CONFIG_TRUSTED_ANCHORS_DISABLED")

    if not bound_account:
        _append_unique(maintenance_reasons, "ACCOUNT_NOT_BOUND")
    elif not account_exists:
        _append_unique(maintenance_reasons, "ACCOUNT_NOT_FOUND")

    if bound_account and not node_key_authorized:
        _append_unique(maintenance_reasons, "NODE_KEY_NOT_AUTHORIZED")

    banned = bool(account_record.get("banned", False))
    locked = bool(account_record.get("locked", False))
    if banned:
        _append_unique(maintenance_reasons, "ACCOUNT_BANNED")
    if locked:
        _append_unique(maintenance_reasons, "ACCOUNT_LOCKED")

    poh_tier_required = _required_poh_tier(requested_roles)
    try:
        poh_tier_actual = int(account_record.get("poh_tier") or 0)
    except Exception:
        poh_tier_actual = 0
    if poh_tier_actual < poh_tier_required:
        _append_unique(maintenance_reasons, "POH_TIER_INSUFFICIENT")

    reputation_required_milli = _required_reputation_milli(requested_roles)
    reputation_actual_milli = account_reputation_units(account_record, default=0)
    if reputation_actual_milli < reputation_required_milli:
        _append_unique(maintenance_reasons, "REPUTATION_INSUFFICIENT")

    active_roles, suspended_roles = _role_state_lists(state, bound_account)

    effective_roles: list[str] = []
    if not hard_fail_reasons and not maintenance_reasons:
        if requested_roles:
            effective_roles.append("general_service")
        for role in requested_roles:
            if role == "general_service":
                continue
            if role == "validator":
                if bft_requested and role in active_roles:
                    effective_roles.append(role)
                elif bft_requested:
                    _append_unique(maintenance_reasons, "ROLE_NOT_ACTIVE")
            elif role in {"helper", "node_operator", "storage_operator"}:
                # Helper/storage currently derive from node operator posture.
                needed = "node_operator" if role in {"helper", "storage_operator"} else role
                if needed in active_roles:
                    effective_roles.append(role)
                else:
                    _append_unique(maintenance_reasons, "ROLE_NOT_ACTIVE")
            elif role in _ALLOWED_SERVICE_ROLES:
                effective_roles.append(role)

    if maintenance_reasons:
        effective_roles = []

    helper_effective = bool(
        helper_requested and "helper" in effective_roles and not hard_fail_reasons and not maintenance_reasons
    )
    bft_effective = bool(
        bft_requested and "validator" in effective_roles and not hard_fail_reasons and not maintenance_reasons
    )

    return ProductionPreflightResult(
        hard_fail_reasons=tuple(sorted(set(hard_fail_reasons))),
        maintenance_reasons=tuple(sorted(set(maintenance_reasons))),
        bound_account=bound_account,
        account_exists=account_exists,
        node_key_authorized=node_key_authorized,
        poh_tier_required=int(poh_tier_required),
        poh_tier_actual=int(poh_tier_actual),
        reputation_required_milli=int(reputation_required_milli),
        reputation_actual_milli=int(reputation_actual_milli),
        banned=banned,
        locked=locked,
        active_roles=active_roles,
        suspended_roles=suspended_roles,
        effective_roles=tuple(sorted(set(effective_roles))),
        helper_effective=helper_effective,
        bft_effective=bft_effective,
    )
