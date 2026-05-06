from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping

from weall.runtime.reputation_units import account_reputation_units

Json = dict[str, Any]


@dataclass(frozen=True, slots=True)
class ResponsibilityEvaluation:
    name: str
    status: str
    eligible: bool
    active: bool
    reasons: tuple[str, ...]
    requirements: tuple[str, ...]
    details: Json

    def as_dict(self) -> Json:
        return {
            "name": self.name,
            "status": self.status,
            "eligible": bool(self.eligible),
            "active": bool(self.active),
            "reasons": list(self.reasons),
            "requirements": list(self.requirements),
            "details": dict(self.details),
        }


def _as_str(value: Any) -> str:
    try:
        return str(value or "").strip()
    except Exception:
        return ""


def _as_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except Exception:
        return int(default)


def _as_dict(value: Any) -> Json:
    return value if isinstance(value, dict) else {}


def _append_unique(items: list[str], value: str) -> None:
    if value and value not in items:
        items.append(value)


def account_record(state: Mapping[str, Any], account_id: str) -> Mapping[str, Any]:
    accounts = state.get("accounts")
    if not account_id or not isinstance(accounts, dict):
        return {}
    rec = accounts.get(account_id)
    return rec if isinstance(rec, dict) else {}


def node_operator_bucket(state: Mapping[str, Any]) -> Mapping[str, Any]:
    roles = state.get("roles")
    if not isinstance(roles, dict):
        return {}
    bucket = roles.get("node_operators")
    return bucket if isinstance(bucket, dict) else {}


def node_operator_record(state: Mapping[str, Any], account_id: str) -> Mapping[str, Any]:
    by_id = node_operator_bucket(state).get("by_id")
    if not isinstance(by_id, dict):
        return {}
    rec = by_id.get(account_id)
    return rec if isinstance(rec, dict) else {}


def active_node_operator_accounts(state: Mapping[str, Any]) -> set[str]:
    active = node_operator_bucket(state).get("active_set")
    if not isinstance(active, list):
        return set()
    return {str(v).strip() for v in active if str(v).strip()}


def is_node_operator_active(state: Mapping[str, Any], account_id: str) -> bool:
    rec = node_operator_record(state, account_id)
    return bool(rec.get("active", False)) or account_id in active_node_operator_accounts(state)


def active_node_pubkeys_for_account(account: Mapping[str, Any]) -> tuple[str, ...]:
    out: list[str] = []
    seen: set[str] = set()
    devices = account.get("devices")
    by_id = devices.get("by_id") if isinstance(devices, dict) else None
    if not isinstance(by_id, dict):
        return ()
    for rec_any in by_id.values():
        rec = _as_dict(rec_any)
        if bool(rec.get("revoked", False)):
            continue
        if _as_str(rec.get("device_type")).lower() != "node":
            continue
        pubkey = _as_str(rec.get("pubkey"))
        if pubkey and pubkey not in seen:
            out.append(pubkey)
            seen.add(pubkey)
    return tuple(sorted(out))


def node_key_owner_sets(state: Mapping[str, Any]) -> dict[str, set[str]]:
    owners: dict[str, set[str]] = {}
    accounts = state.get("accounts")
    if not isinstance(accounts, dict):
        return owners
    for account_id_raw, account_any in accounts.items():
        account_id = _as_str(account_id_raw)
        if not account_id:
            continue
        for pubkey in active_node_pubkeys_for_account(_as_dict(account_any)):
            owners.setdefault(pubkey, set()).add(account_id)
    return owners


def node_key_owner_map(state: Mapping[str, Any]) -> dict[str, str]:
    """Return a compatibility first-owner map for diagnostics.

    Production uniqueness checks MUST use node_key_owner_sets() because a node
    key shared by multiple accounts is not unique for any of those accounts.
    """
    return {pubkey: sorted(owners)[0] for pubkey, owners in node_key_owner_sets(state).items() if owners}


def has_registered_node_key(state: Mapping[str, Any], account_id: str, *, node_pubkey: str = "") -> bool:
    active = set(active_node_pubkeys_for_account(account_record(state, account_id)))
    if node_pubkey:
        return node_pubkey in active
    return bool(active)


def has_unique_node_key(state: Mapping[str, Any], account_id: str, *, node_pubkey: str = "") -> bool:
    node_keys = list(active_node_pubkeys_for_account(account_record(state, account_id)))
    if node_pubkey:
        node_keys = [k for k in node_keys if k == node_pubkey]
    if not node_keys:
        return False
    owners_by_key = node_key_owner_sets(state)
    for pubkey in node_keys:
        owners = owners_by_key.get(pubkey, set())
        if owners == {account_id}:
            return True
    return False


def duplicate_node_keys_for_account(state: Mapping[str, Any], account_id: str) -> tuple[str, ...]:
    account_keys = set(active_node_pubkeys_for_account(account_record(state, account_id)))
    if not account_keys:
        return ()
    owners_by_key = node_key_owner_sets(state)
    out = [pubkey for pubkey in account_keys if len(owners_by_key.get(pubkey, set())) > 1]
    return tuple(sorted(out))


def responsibility_record(state: Mapping[str, Any], account_id: str, name: str) -> Mapping[str, Any]:
    responsibilities = node_operator_record(state, account_id).get("responsibilities")
    if not isinstance(responsibilities, dict):
        return {}
    rec = responsibilities.get(name)
    return rec if isinstance(rec, dict) else {}


def baseline_requirements(state: Mapping[str, Any], account_id: str, *, node_pubkey: str = "") -> tuple[list[str], Json]:
    account = account_record(state, account_id)
    reasons: list[str] = []
    details: Json = {
        "account_id": account_id,
        "poh_tier_required": 2,
        "poh_tier_actual": _as_int(account.get("poh_tier"), 0),
        "node_pubkey": node_pubkey,
        "duplicate_node_pubkeys": list(duplicate_node_keys_for_account(state, account_id)),
    }
    if not account:
        _append_unique(reasons, "account_not_found")
        return reasons, details
    if bool(account.get("banned", False)):
        _append_unique(reasons, "account_banned")
    if bool(account.get("locked", False)):
        _append_unique(reasons, "account_locked")
    if _as_int(account.get("poh_tier"), 0) < 2:
        _append_unique(reasons, "poh_tier_insufficient")
    if not has_registered_node_key(state, account_id, node_pubkey=node_pubkey):
        _append_unique(reasons, "node_key_missing")
    elif not has_unique_node_key(state, account_id, node_pubkey=node_pubkey):
        _append_unique(reasons, "node_key_not_unique")
    return reasons, details


def evaluate_baseline_node_operator(state: Mapping[str, Any], account_id: str, *, node_pubkey: str = "") -> ResponsibilityEvaluation:
    rec = node_operator_record(state, account_id)
    enrolled = bool(rec.get("enrolled", False))
    active = is_node_operator_active(state, account_id)
    details: Json = {"account_id": account_id, "enrolled": enrolled, "node_pubkey": node_pubkey}
    if not enrolled:
        return ResponsibilityEvaluation("baseline_node_operator", "not_opted_in", False, False, ("not_enrolled",), ("enrolled", "tier2", "active_node_key", "unrestricted_account"), details)
    reasons, extra = baseline_requirements(state, account_id, node_pubkey=node_pubkey)
    details.update(extra)
    status = "active" if active else ("blocked" if reasons else "eligible")
    return ResponsibilityEvaluation("baseline_node_operator", status, not reasons, active, tuple(reasons), ("enrolled", "tier2", "active_node_key", "unique_node_key", "unrestricted_account"), details)


def evaluate_storage_responsibility(state: Mapping[str, Any], account_id: str, *, node_pubkey: str = "") -> ResponsibilityEvaluation:
    rec = responsibility_record(state, account_id, "storage")
    opted_in = bool(rec.get("opted_in", False))
    active_flag = bool(rec.get("active", False))
    declared = _as_int(rec.get("declared_capacity_bytes"), 0)
    proven = _as_int(rec.get("proven_capacity_bytes"), 0)
    allocated = _as_int(rec.get("allocated_capacity_bytes"), 0)
    proof_status = _as_str(rec.get("proof_status")) or "not_requested"
    # Compatibility for historical states/tests that carried an already-proven
    # capacity value before proof_status was introduced. New production flows
    # still set proof_status=verified through the system verifier path.
    if proof_status == "not_requested" and proven > 0:
        proof_status = "proven"
    details: Json = {
        "account_id": account_id,
        "opted_in": opted_in,
        "declared_capacity_bytes": declared,
        "proven_capacity_bytes": proven,
        "allocated_capacity_bytes": allocated,
        "proof_status": proof_status,
        "latest_challenge_id": _as_str(rec.get("latest_challenge_id")),
        "node_pubkey": node_pubkey,
    }
    if not opted_in:
        return ResponsibilityEvaluation("storage", "not_opted_in", False, False, ("not_opted_in",), ("baseline_node_operator_active", "storage_opt_in", "declared_capacity", "capacity_proof"), details)
    reasons: list[str] = []
    baseline = evaluate_baseline_node_operator(state, account_id, node_pubkey=node_pubkey)
    if not baseline.active:
        _append_unique(reasons, "baseline_node_operator_inactive")
    if not baseline.eligible:
        for reason in baseline.reasons:
            _append_unique(reasons, reason)
    if declared <= 0:
        _append_unique(reasons, "declared_capacity_required")
    if proven <= 0:
        _append_unique(reasons, "capacity_proof_pending")
    if proven > declared and declared > 0:
        _append_unique(reasons, "proven_capacity_exceeds_declared_capacity")
    if proof_status not in ("verified", "proven", "active"):
        if proof_status == "challenge_open":
            _append_unique(reasons, "capacity_challenge_open")
        elif proof_status == "verification_pending":
            _append_unique(reasons, "capacity_verification_pending")
        elif proof_status == "failed":
            _append_unique(reasons, "capacity_proof_failed")
        elif proof_status == "expired":
            _append_unique(reasons, "capacity_proof_expired")
    active = bool(active_flag and proven > 0 and baseline.active and proof_status in ("verified", "proven", "active") and proven <= declared)
    if active:
        status = "active"
    elif "capacity_challenge_open" in reasons:
        status = "challenge_open"
    elif "capacity_verification_pending" in reasons:
        status = "verification_pending"
    elif "capacity_proof_failed" in reasons:
        status = "proof_failed"
    elif "capacity_proof_expired" in reasons:
        status = "proof_expired"
    elif "capacity_proof_pending" in reasons:
        status = "proof_pending"
    else:
        status = "blocked" if reasons else "eligible"
    return ResponsibilityEvaluation("storage", status, not reasons, active, tuple(reasons), ("baseline_node_operator_active", "storage_opt_in", "declared_capacity", "capacity_proof"), details)


def evaluate_validator_responsibility(state: Mapping[str, Any], account_id: str, *, node_pubkey: str = "") -> ResponsibilityEvaluation:
    account = account_record(state, account_id)
    rec = responsibility_record(state, account_id, "validator")
    opted_in = bool(rec.get("opted_in", False))
    active_flag = bool(rec.get("active", False))
    required = _as_int(rec.get("reputation_required_milli"), 5000)
    actual = account_reputation_units(account, default=0)
    readiness = _as_str(rec.get("readiness_status")) or "not_requested"
    details: Json = {"account_id": account_id, "opted_in": opted_in, "readiness_status": readiness, "reputation_required_milli": required, "reputation_actual_milli": actual, "node_pubkey": node_pubkey}
    if not opted_in:
        return ResponsibilityEvaluation("validator", "not_opted_in", False, False, ("not_opted_in",), ("baseline_node_operator_active", "validator_opt_in", "reputation", "validator_readiness"), details)
    reasons: list[str] = []
    baseline = evaluate_baseline_node_operator(state, account_id, node_pubkey=node_pubkey)
    if not baseline.active:
        _append_unique(reasons, "baseline_node_operator_inactive")
    if not baseline.eligible:
        for reason in baseline.reasons:
            _append_unique(reasons, reason)
    if actual < required:
        _append_unique(reasons, "validator_reputation_insufficient")
    if readiness not in ("ready", "active"):
        _append_unique(reasons, "validator_readiness_pending")
    active = bool(active_flag and not reasons)
    status = "active" if active else ("readiness_pending" if "validator_readiness_pending" in reasons else ("blocked" if reasons else "eligible"))
    return ResponsibilityEvaluation("validator", status, not reasons, active, tuple(reasons), ("baseline_node_operator_active", "validator_opt_in", "reputation", "validator_readiness"), details)


def evaluate_node_operator_responsibilities(state: Mapping[str, Any], account_id: str, *, node_pubkey: str = "") -> Json:
    return {
        "baseline": evaluate_baseline_node_operator(state, account_id, node_pubkey=node_pubkey).as_dict(),
        "validator": evaluate_validator_responsibility(state, account_id, node_pubkey=node_pubkey).as_dict(),
        "storage": evaluate_storage_responsibility(state, account_id, node_pubkey=node_pubkey).as_dict(),
    }


def first_blocking_reason(evaluation: ResponsibilityEvaluation, *, default: str = "blocked") -> str:
    return evaluation.reasons[0] if evaluation.reasons else default
