from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping

from weall.runtime.reputation_units import account_reputation_units
from weall.runtime.poh.state import effective_poh_tier
from weall.runtime.storage_revalidation_scheduler import (
    storage_max_failed_challenges,
    storage_max_missed_challenges,
    storage_min_availability_score_milli,
    storage_revalidation_window_blocks,
)

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


def _state_height(state: Mapping[str, Any]) -> int:
    return _as_int(state.get("height"), 0)


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
    effective_tier = effective_poh_tier(dict(state), account_id)
    details: Json = {
        "account_id": account_id,
        "poh_tier_required": 2,
        "poh_tier_actual": effective_tier,
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
    if effective_tier < 2:
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
    used = _as_int(rec.get("used_capacity_bytes"), 0)
    reserved = _as_int(rec.get("reserved_capacity_bytes"), 0)
    probed = _as_int(rec.get("probed_capacity_bytes"), 0)
    proof_expires = _as_int(rec.get("proof_expires_height"), 0)
    current_height = _state_height(state)
    proof_status = _as_str(rec.get("proof_status")) or "not_requested"
    details: Json = {
        "account_id": account_id, "opted_in": opted_in, "declared_capacity_bytes": declared,
        "reserved_capacity_bytes": reserved, "probed_capacity_bytes": probed, "proven_capacity_bytes": proven,
        "allocated_capacity_bytes": allocated, "used_capacity_bytes": used, "available_capacity_bytes": max(0, proven - allocated),
        "proof_status": proof_status, "proof_expires_height": proof_expires, "current_height": current_height,
        "latest_challenge_id": _as_str(rec.get("latest_challenge_id")),
        "failed_challenge_count": _as_int(rec.get("failed_challenge_count"), 0),
        "missed_challenge_count": _as_int(rec.get("missed_challenge_count"), 0),
        "availability_score_milli": _as_int(rec.get("availability_score_milli"), 0),
        "revalidation_window_blocks": storage_revalidation_window_blocks(state),
        "failed_challenge_limit": storage_max_failed_challenges(state),
        "missed_challenge_limit": storage_max_missed_challenges(state),
        "availability_score_minimum_milli": storage_min_availability_score_milli(state),
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
    if proof_status not in ("verified", "active"):
        if proof_status in ("challenge_open", "probe_open"):
            _append_unique(reasons, "capacity_probe_open")
        elif proof_status == "verification_pending":
            _append_unique(reasons, "capacity_verification_pending")
        elif proof_status == "failed":
            _append_unique(reasons, "capacity_proof_failed")
        elif proof_status == "expired":
            _append_unique(reasons, "capacity_proof_expired")
    if proof_expires > 0 and current_height > proof_expires:
        _append_unique(reasons, "capacity_proof_expired")
    elif proof_expires > 0 and proof_expires - current_height <= storage_revalidation_window_blocks(state):
        _append_unique(reasons, "capacity_revalidation_due")
    if _as_int(rec.get("failed_challenge_count"), 0) >= storage_max_failed_challenges(state):
        _append_unique(reasons, "capacity_failed_challenge_limit_reached")
    if _as_int(rec.get("missed_challenge_count"), 0) >= storage_max_missed_challenges(state):
        _append_unique(reasons, "capacity_missed_challenge_limit_reached")
    if _as_int(rec.get("availability_score_milli"), 1000) < storage_min_availability_score_milli(state):
        _append_unique(reasons, "capacity_availability_score_below_minimum")
    if allocated > proven and proven > 0:
        _append_unique(reasons, "allocated_capacity_exceeds_proven_capacity")
    if used > allocated and allocated > 0:
        _append_unique(reasons, "used_capacity_exceeds_allocated_capacity")
    active = bool(active_flag and proven > 0 and baseline.active and proof_status in ("verified", "active") and proven <= declared and (proof_expires <= 0 or current_height <= proof_expires) and allocated <= proven)
    if active:
        status = "active"
    elif "capacity_probe_open" in reasons:
        status = "probe_open"
    elif "capacity_verification_pending" in reasons:
        status = "verification_pending"
    elif "capacity_proof_failed" in reasons:
        status = "proof_failed"
    elif "capacity_proof_expired" in reasons:
        status = "proof_expired"
    elif "capacity_failed_challenge_limit_reached" in reasons or "capacity_missed_challenge_limit_reached" in reasons or "capacity_availability_score_below_minimum" in reasons:
        status = "paused"
    elif "capacity_revalidation_due" in reasons:
        status = "revalidation_due"
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
    readiness_expires = _as_int(rec.get("readiness_expires_height"), 0)
    current_height = _state_height(state)
    details: Json = {
        "account_id": account_id,
        "opted_in": opted_in,
        "readiness_status": readiness,
        "readiness_expires_height": readiness_expires,
        "current_height": current_height,
        "reputation_required_milli": required,
        "reputation_actual_milli": actual,
        "node_pubkey": node_pubkey,
        "readiness_receipt_hash": _as_str(rec.get("readiness_receipt_hash")),
        "manifest_hash": _as_str(rec.get("manifest_hash")),
        "tx_index_hash": _as_str(rec.get("tx_index_hash")),
        "runtime_profile_hash": _as_str(rec.get("runtime_profile_hash")),
        "chain_id": _as_str(rec.get("chain_id")),
        "schema_version": _as_str(rec.get("schema_version")),
        "protocol_version": _as_str(rec.get("protocol_version")),
        "bft_pubkey": _as_str(rec.get("bft_pubkey")),
    }
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
    if readiness not in ("ready", "active", "verified"):
        _append_unique(reasons, "validator_readiness_pending")
    if readiness_expires > 0 and current_height > readiness_expires:
        _append_unique(reasons, "validator_readiness_expired")
    active = bool(active_flag and not reasons)
    if active:
        status = "active"
    elif "validator_reputation_insufficient" in reasons:
        status = "reputation_insufficient"
    elif "validator_readiness_expired" in reasons:
        status = "readiness_expired"
    elif "validator_readiness_pending" in reasons:
        status = "readiness_pending"
    else:
        status = "blocked" if reasons else "eligible"
    return ResponsibilityEvaluation("validator", status, not reasons, active, tuple(reasons), ("baseline_node_operator_active", "validator_opt_in", "reputation", "validator_readiness"), details)


def evaluate_helper_responsibility(state: Mapping[str, Any], account_id: str, *, node_pubkey: str = "") -> ResponsibilityEvaluation:
    account = account_record(state, account_id)
    rec = responsibility_record(state, account_id, "helper")
    opted_in = bool(rec.get("opted_in", False))
    active_flag = bool(rec.get("active", False))
    required = _as_int(rec.get("reputation_required_milli"), 2000)
    actual = account_reputation_units(account, default=0)
    details: Json = {
        "account_id": account_id,
        "opted_in": opted_in,
        "reputation_required_milli": required,
        "reputation_actual_milli": actual,
        "node_pubkey": node_pubkey,
        "helper_endpoint_commitment": _as_str(rec.get("helper_endpoint_commitment")),
        "helper_capacity_units": _as_int(rec.get("helper_capacity_units"), 0),
    }
    if not opted_in:
        # Exact helper opt-in is required for newly enrolled operators. For
        # historical fixtures and pre-Batch-616 ledgers that contain an already
        # active node-operator record but no responsibilities object at all,
        # preserve deterministic replay by treating the coarse helper request as
        # a legacy migrated helper opt-in. New ROLE_NODE_OPERATOR_ACTIVATE stamps
        # responsibilities, so it remains fail-closed without NODE_OPERATOR_HELPER_OPT_IN.
        op_rec = node_operator_record(state, account_id)
        if bool(op_rec.get("enrolled", False)) and "responsibilities" not in op_rec:
            reasons: list[str] = []
            baseline = evaluate_baseline_node_operator(state, account_id, node_pubkey=node_pubkey)
            if not baseline.active:
                _append_unique(reasons, "baseline_node_operator_inactive")
            if not baseline.eligible:
                legacy_reasons = set(baseline.reasons)
                if legacy_reasons != {"node_key_missing"}:
                    for reason in baseline.reasons:
                        _append_unique(reasons, reason)
            if actual < required:
                _append_unique(reasons, "helper_reputation_insufficient")
            legacy_details = dict(details)
            legacy_details["legacy_migration_compat"] = True
            active = not reasons
            return ResponsibilityEvaluation(
                "helper",
                "active" if active else "blocked",
                not reasons,
                active,
                tuple(reasons),
                ("baseline_node_operator_active", "helper_opt_in", "reputation", "active_node_key"),
                legacy_details,
            )
        return ResponsibilityEvaluation(
            "helper",
            "not_opted_in",
            False,
            False,
            ("not_opted_in",),
            ("baseline_node_operator_active", "helper_opt_in", "reputation", "active_node_key"),
            details,
        )
    reasons: list[str] = []
    baseline = evaluate_baseline_node_operator(state, account_id, node_pubkey=node_pubkey)
    if not baseline.active:
        _append_unique(reasons, "baseline_node_operator_inactive")
    if not baseline.eligible:
        for reason in baseline.reasons:
            _append_unique(reasons, reason)
    if actual < required:
        _append_unique(reasons, "helper_reputation_insufficient")
    active = bool(active_flag and not reasons)
    status = "active" if active else ("blocked" if reasons else "eligible")
    return ResponsibilityEvaluation(
        "helper",
        status,
        not reasons,
        active,
        tuple(reasons),
        ("baseline_node_operator_active", "helper_opt_in", "reputation", "active_node_key"),
        details,
    )


def evaluate_node_operator_responsibilities(state: Mapping[str, Any], account_id: str, *, node_pubkey: str = "") -> Json:
    return {
        "baseline": evaluate_baseline_node_operator(state, account_id, node_pubkey=node_pubkey).as_dict(),
        "validator": evaluate_validator_responsibility(state, account_id, node_pubkey=node_pubkey).as_dict(),
        "storage": evaluate_storage_responsibility(state, account_id, node_pubkey=node_pubkey).as_dict(),
        "helper": evaluate_helper_responsibility(state, account_id, node_pubkey=node_pubkey).as_dict(),
    }


def first_blocking_reason(evaluation: ResponsibilityEvaluation, *, default: str = "blocked") -> str:
    return evaluation.reasons[0] if evaluation.reasons else default
