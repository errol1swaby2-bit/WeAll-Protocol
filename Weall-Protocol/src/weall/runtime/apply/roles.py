from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from weall.ledger.roles_schema import ensure_roles_schema, set_treasury_signers
from weall.runtime.tx_admission import TxEnvelope
from weall.runtime.reputation_units import account_reputation_units
from weall.runtime.validator_readiness_runner import (
    ValidatorReadinessError,
    validate_validator_readiness_payload,
)
from weall.runtime.node_operator_responsibilities import (
    active_node_pubkeys_for_account as responsibility_active_node_pubkeys_for_account,
    is_node_operator_active,
)

Json = dict[str, Any]


@dataclass
class RolesApplyError(Exception):
    code: str
    reason: str
    details: Json | None = None

    def __str__(self) -> str:
        return f"{self.code}:{self.reason}"


def _as_str(v: Any) -> str:
    return str(v).strip() if isinstance(v, (str, int, float)) else ""


def _as_int(v: Any, default: int = 0) -> int:
    try:
        return int(v)
    except Exception:
        return int(default)


def _as_list(v: Any) -> list[Any]:
    return v if isinstance(v, list) else []


def _as_dict(v: Any) -> Json:
    return v if isinstance(v, dict) else {}


def _touch(by_id: Json, acct: str) -> Json:
    rec = by_id.get(acct)
    if not isinstance(rec, dict):
        rec = {"account_id": acct, "enrolled": False, "active": False}
    rec.setdefault("account_id", acct)
    return rec


def _pick_account(payload: Json, *keys: str) -> str:
    for k in keys:
        v = payload.get(k)
        s = _as_str(v).strip()
        if s:
            return s
    return ""


def _ensure_roles(ledger: Json) -> Json:
    ensure_roles_schema(ledger)
    roles = ledger.get("roles")
    return roles if isinstance(roles, dict) else {}



_ROLE_ELIGIBILITY_ALIASES: dict[str, tuple[str, ...]] = {
    "juror": ("juror", "Juror", "ROLE_JUROR", "ROLE_JUROR_ACTIVATE"),
    "node_operator": (
        "node_operator",
        "NodeOperator",
        "Node Operator",
        "ROLE_NODE_OPERATOR",
        "ROLE_NODE_OPERATOR_ACTIVATE",
    ),
    "validator": ("validator", "Validator", "ROLE_VALIDATOR", "ROLE_VALIDATOR_ACTIVATE"),
    "gov_executor": ("gov_executor", "GovExecutor", "ROLE_GOV_EXECUTOR", "ROLE_GOV_EXECUTOR_SET"),
    "emissary": ("emissary", "Emissary", "ROLE_EMISSARY", "ROLE_EMISSARY_SEAT"),
}


def _account_for_activation(ledger: Json, acct: str) -> Json:
    accounts = _as_dict(ledger.get("accounts"))
    account = accounts.get(acct)
    if not isinstance(account, dict):
        raise RolesApplyError("not_found", "account_not_found", {"account_id": acct})
    return account


def _role_eligibility_revoked(ledger: Json, acct: str, role: str) -> bool:
    rep = _as_dict(ledger.get("reputation"))
    elig = _as_dict(rep.get("role_eligibility"))
    rec = _as_dict(elig.get(acct))
    roles = _as_dict(rec.get("roles"))
    aliases = _ROLE_ELIGIBILITY_ALIASES.get(role, (role,))
    return any(alias in roles and bool(roles.get(alias)) is False for alias in aliases)


def _require_role_activation_eligible(
    ledger: Json,
    acct: str,
    *,
    role: str,
    minimum_reputation_milli: int = 0,
) -> Json:
    account = _account_for_activation(ledger, acct)
    if bool(account.get("banned", False)) or bool(account.get("locked", False)):
        raise RolesApplyError("forbidden", "account_restricted", {"account_id": acct, "role": role})
    if _as_int(account.get("poh_tier"), 0) < 2:
        raise RolesApplyError("forbidden", "live_verification_required", {"account_id": acct, "role": role})
    if _role_eligibility_revoked(ledger, acct, role):
        raise RolesApplyError("forbidden", "role_eligibility_revoked", {"account_id": acct, "role": role})
    required = max(0, int(minimum_reputation_milli))
    actual = account_reputation_units(account, default=0)
    if actual < required:
        raise RolesApplyError(
            "forbidden",
            "reputation_insufficient",
            {
                "account_id": acct,
                "role": role,
                "required_milli": int(required),
                "actual_milli": int(actual),
            },
        )
    return account


def _role_required_reputation_milli(ledger: Json, payload: Json, role: str, default: int = 0) -> int:
    params = _as_dict(ledger.get("params"))
    for key in (
        "reputation_required_milli",
        f"{role}_reputation_required_milli",
        f"{role}_minimum_reputation_milli",
    ):
        if key in payload:
            return max(0, _as_int(payload.get(key), default))
        if key in params:
            return max(0, _as_int(params.get(key), default))
    return max(0, int(default))


def _ensure_node_operator_responsibilities(rec: Json) -> Json:
    responsibilities = rec.get("responsibilities")
    if not isinstance(responsibilities, dict):
        responsibilities = {}
        rec["responsibilities"] = responsibilities
    validator = responsibilities.get("validator")
    if not isinstance(validator, dict):
        validator = {}
    validator.setdefault("opted_in", False)
    validator.setdefault("active", False)
    validator.setdefault("readiness_status", "not_requested")
    validator.setdefault("reputation_required_milli", 5000)
    responsibilities["validator"] = validator
    storage = responsibilities.get("storage")
    if not isinstance(storage, dict):
        storage = {}
    storage.setdefault("opted_in", False)
    storage.setdefault("active", False)
    storage.setdefault("declared_capacity_bytes", 0)
    storage.setdefault("proven_capacity_bytes", 0)
    storage.setdefault("allocated_capacity_bytes", 0)
    storage.setdefault("proof_status", "not_requested")
    responsibilities["storage"] = storage
    return responsibilities


def _has_storage_responsibility_intent(payload: Json) -> bool:
    if bool(payload.get("storage_opt_in", False)):
        return True
    if payload.get("declared_capacity_bytes") is not None or payload.get("storage_capacity_bytes") is not None:
        return True
    if payload.get("storage_endpoint_commitment") is not None:
        return True
    responsibilities = payload.get("responsibilities")
    if isinstance(responsibilities, dict):
        storage = responsibilities.get("storage")
        if isinstance(storage, dict):
            return bool(storage.get("opted_in", False)) or storage.get("declared_capacity_bytes") is not None
    return False


def _payload_storage_field(payload: Json, key: str, default: Any = None) -> Any:
    if key in payload:
        return payload.get(key)
    responsibilities = payload.get("responsibilities")
    if isinstance(responsibilities, dict):
        storage = responsibilities.get("storage")
        if isinstance(storage, dict) and key in storage:
            return storage.get(key)
    return default


def _has_validator_responsibility_intent(payload: Json) -> bool:
    if bool(payload.get("validator_opt_in", False)):
        return True
    if payload.get("validator_readiness_commitment") is not None:
        return True
    if payload.get("validator_endpoint_commitment") is not None:
        return True
    responsibilities = payload.get("responsibilities")
    if isinstance(responsibilities, dict):
        validator = responsibilities.get("validator")
        if isinstance(validator, dict):
            return bool(validator.get("opted_in", False))
    return False


def _payload_validator_field(payload: Json, key: str, default: Any = None) -> Any:
    if key in payload:
        return payload.get(key)
    responsibilities = payload.get("responsibilities")
    if isinstance(responsibilities, dict):
        validator = responsibilities.get("validator")
        if isinstance(validator, dict) and key in validator:
            return validator.get(key)
    return default


def _active_node_pubkeys_for_account(ledger: Json, acct: str) -> set[str]:
    account = _as_dict(_as_dict(ledger.get("accounts")).get(acct))
    return set(responsibility_active_node_pubkeys_for_account(account))


def _apply_node_validator_responsibility_opt_in(ledger: Json, *, ops: Json, acct: str, rec: Json, payload: Json, nonce: int) -> None:
    account = _as_dict(_as_dict(ledger.get("accounts")).get(acct))
    if not account:
        raise RolesApplyError("not_found", "account_not_found", {"account_id": acct})
    if bool(account.get("banned", False)) or bool(account.get("locked", False)):
        raise RolesApplyError("forbidden", "account_restricted", {"account_id": acct})
    if _as_int(account.get("poh_tier"), 0) < 2:
        raise RolesApplyError("forbidden", "live_verification_required", {"account_id": acct})

    if not is_node_operator_active(ledger, acct):
        raise RolesApplyError("forbidden", "node_operator_status_required", {"account_id": acct})

    reputation_required = _as_int(_payload_validator_field(payload, "reputation_required_milli", 5000), 5000)
    if reputation_required < 0:
        reputation_required = 5000
    reputation_actual = account_reputation_units(account, default=0)
    if reputation_actual < reputation_required:
        raise RolesApplyError(
            "forbidden",
            "validator_reputation_insufficient",
            {
                "account_id": acct,
                "required_milli": int(reputation_required),
                "actual_milli": int(reputation_actual),
            },
        )

    node_pubkey = _as_str(payload.get("node_pubkey") or payload.get("node_public_key"))
    if node_pubkey and node_pubkey not in _active_node_pubkeys_for_account(ledger, acct):
        raise RolesApplyError("forbidden", "node_key_not_registered", {"account_id": acct})

    responsibilities = _ensure_node_operator_responsibilities(rec)
    validator = _as_dict(responsibilities.get("validator"))
    validator.update(
        {
            "opted_in": True,
            "active": False,
            "readiness_status": "pending",
            "reputation_required_milli": int(reputation_required),
            "reputation_actual_milli": int(reputation_actual),
            "updated_at_nonce": int(nonce),
        }
    )
    readiness_commitment = _as_str(
        payload.get("validator_readiness_commitment")
        or _payload_validator_field(payload, "validator_readiness_commitment")
    )
    endpoint_commitment = _as_str(
        payload.get("validator_endpoint_commitment")
        or _payload_validator_field(payload, "validator_endpoint_commitment")
    )
    if readiness_commitment:
        validator["validator_readiness_commitment"] = readiness_commitment
    if endpoint_commitment:
        validator["validator_endpoint_commitment"] = endpoint_commitment
    if node_pubkey:
        validator["node_pubkey"] = node_pubkey
    responsibilities["validator"] = validator


def _apply_node_storage_responsibility_opt_in(ledger: Json, *, ops: Json, acct: str, rec: Json, payload: Json, nonce: int) -> None:
    account = _as_dict(_as_dict(ledger.get("accounts")).get(acct))
    if not account:
        raise RolesApplyError("not_found", "account_not_found", {"account_id": acct})
    if bool(account.get("banned", False)) or bool(account.get("locked", False)):
        raise RolesApplyError("forbidden", "account_restricted", {"account_id": acct})
    if _as_int(account.get("poh_tier"), 0) < 2:
        raise RolesApplyError("forbidden", "live_verification_required", {"account_id": acct})

    if not is_node_operator_active(ledger, acct):
        raise RolesApplyError("forbidden", "node_operator_status_required", {"account_id": acct})

    declared_raw = payload.get("declared_capacity_bytes", payload.get("storage_capacity_bytes"))
    if declared_raw is None:
        declared_raw = _payload_storage_field(payload, "declared_capacity_bytes", _payload_storage_field(payload, "storage_capacity_bytes", 0))
    declared = _as_int(declared_raw, 0)
    if declared <= 0:
        raise RolesApplyError("invalid_payload", "declared_capacity_required", {"account_id": acct})

    node_pubkey = _as_str(payload.get("node_pubkey") or payload.get("node_public_key"))
    if node_pubkey and node_pubkey not in _active_node_pubkeys_for_account(ledger, acct):
        raise RolesApplyError("forbidden", "node_key_not_registered", {"account_id": acct})

    responsibilities = _ensure_node_operator_responsibilities(rec)
    storage = _as_dict(responsibilities.get("storage"))
    prior_proven = _as_int(storage.get("proven_capacity_bytes"), 0)
    prior_allocated = _as_int(storage.get("allocated_capacity_bytes"), 0)
    storage.update(
        {
            "opted_in": True,
            "active": False,
            "declared_capacity_bytes": declared,
            "proven_capacity_bytes": prior_proven,
            "allocated_capacity_bytes": prior_allocated,
            "reserved_capacity_bytes": _as_int(storage.get("reserved_capacity_bytes"), 0),
            "probed_capacity_bytes": _as_int(storage.get("probed_capacity_bytes"), 0),
            "used_capacity_bytes": _as_int(storage.get("used_capacity_bytes"), 0),
            "proof_status": "probe_pending",
            "updated_at_nonce": int(nonce),
        }
    )
    endpoint_commitment = _as_str(payload.get("storage_endpoint_commitment") or _payload_storage_field(payload, "storage_endpoint_commitment"))
    if endpoint_commitment:
        storage["storage_endpoint_commitment"] = endpoint_commitment
    if node_pubkey:
        storage["node_pubkey"] = node_pubkey
    responsibilities["storage"] = storage

def _node_operator_record_for_update(ledger: Json, acct: str) -> tuple[Json, Json, Json]:
    roles = _ensure_roles(ledger)
    ops = roles.get("node_operators")
    if not isinstance(ops, dict):
        ops = {"by_id": {}, "active_set": []}
        roles["node_operators"] = ops
    by_id = ops.get("by_id")
    if not isinstance(by_id, dict):
        by_id = {}
        ops["by_id"] = by_id
    rec = _touch(by_id, acct)
    by_id[acct] = rec
    return ops, by_id, rec


def _apply_node_operator_storage_opt_in_tx(ledger: Json, env: TxEnvelope) -> Json:
    payload = _as_dict(env.payload)
    acct = _pick_account(payload, "account_id", "operator", "node_operator", "target", "account")
    if not acct:
        raise RolesApplyError("invalid_payload", "missing_account_id", {"tx_type": env.tx_type})
    if acct != env.signer:
        raise RolesApplyError("forbidden", "only_account_can_update_storage_responsibility", {"account_id": acct})
    ops, by_id, rec = _node_operator_record_for_update(ledger, acct)
    _apply_node_storage_responsibility_opt_in(ledger, ops=ops, acct=acct, rec=rec, payload=payload, nonce=int(env.nonce))
    by_id[acct] = rec
    return {"applied": "NODE_OPERATOR_STORAGE_OPT_IN", "account_id": acct}


def _apply_node_operator_validator_opt_in_tx(ledger: Json, env: TxEnvelope) -> Json:
    payload = _as_dict(env.payload)
    acct = _pick_account(payload, "account_id", "operator", "node_operator", "target", "account")
    if not acct:
        raise RolesApplyError("invalid_payload", "missing_account_id", {"tx_type": env.tx_type})
    if acct != env.signer:
        raise RolesApplyError("forbidden", "only_account_can_update_validator_responsibility", {"account_id": acct})
    ops, by_id, rec = _node_operator_record_for_update(ledger, acct)
    _apply_node_validator_responsibility_opt_in(ledger, ops=ops, acct=acct, rec=rec, payload=payload, nonce=int(env.nonce))
    by_id[acct] = rec
    return {"applied": "NODE_OPERATOR_VALIDATOR_OPT_IN", "account_id": acct}


def _apply_node_operator_responsibility_update(ledger: Json, env: TxEnvelope) -> Json:
    payload = _as_dict(env.payload)
    acct = _pick_account(payload, "account_id", "operator", "node_operator", "target", "account")
    if not acct:
        raise RolesApplyError("invalid_payload", "missing_account_id", {"tx_type": env.tx_type})
    if acct != env.signer:
        raise RolesApplyError("forbidden", "only_account_can_update_node_operator_responsibilities", {"account_id": acct})
    ops, by_id, rec = _node_operator_record_for_update(ledger, acct)
    updated: list[str] = []
    if _has_storage_responsibility_intent(payload):
        _apply_node_storage_responsibility_opt_in(ledger, ops=ops, acct=acct, rec=rec, payload=payload, nonce=int(env.nonce))
        updated.append("storage")
    if _has_validator_responsibility_intent(payload):
        _apply_node_validator_responsibility_opt_in(ledger, ops=ops, acct=acct, rec=rec, payload=payload, nonce=int(env.nonce))
        updated.append("validator")
    if not updated:
        raise RolesApplyError("invalid_payload", "no_responsibility_update", {"account_id": acct})
    by_id[acct] = rec
    return {"applied": "NODE_OPERATOR_RESPONSIBILITY_UPDATE", "account_id": acct, "updated": sorted(updated)}


def _apply_validator_readiness_verify(ledger: Json, env: TxEnvelope) -> Json:
    _require_system_env(env)
    payload = _as_dict(env.payload)
    acct = _pick_account(payload, "account_id", "operator", "node_operator", "target", "account")
    if not acct:
        raise RolesApplyError("invalid_payload", "missing_account_id", {"tx_type": env.tx_type})
    status = _as_str(payload.get("verification_status") or payload.get("readiness_status") or payload.get("status")).lower()
    if status not in ("verified", "ready", "failed", "rejected"):
        raise RolesApplyError("invalid_payload", "validator_readiness_status_required", {"account_id": acct})
    ops, by_id, rec = _node_operator_record_for_update(ledger, acct)
    responsibilities = _ensure_node_operator_responsibilities(rec)
    validator = _as_dict(responsibilities.get("validator"))
    if not bool(validator.get("opted_in", False)):
        raise RolesApplyError("forbidden", "validator_responsibility_not_opted_in", {"account_id": acct})
    if status in ("verified", "ready"):
        expected_node_pubkey = _as_str(payload.get("node_pubkey") or validator.get("node_pubkey"))
        try:
            readiness = validate_validator_readiness_payload(
                payload,
                account_id=acct,
                expected_node_pubkey=expected_node_pubkey,
                current_height=_as_int(ledger.get("height"), 0),
            )
        except ValidatorReadinessError as exc:
            raise RolesApplyError(
                "invalid_payload",
                "validator_live_readiness_invalid",
                {"account_id": acct, "reason": str(exc)},
            ) from exc
        validator.update(
            {
                "active": True,
                "readiness_status": "verified",
                "manifest_hash": readiness["manifest_hash"],
                "tx_index_hash": readiness["tx_index_hash"],
                "runtime_profile_hash": readiness["runtime_profile_hash"],
                "chain_id": readiness["chain_id"],
                "schema_version": readiness["schema_version"],
                "protocol_version": readiness["protocol_version"],
                "node_pubkey": readiness["node_pubkey"],
                "bft_pubkey": readiness["bft_pubkey"],
                "readiness_checks": readiness["readiness_checks"],
                "readiness_receipt_hash": readiness["readiness_receipt_hash"],
                "readiness_verified_at_nonce": int(env.nonce),
                "readiness_verified_at_height": _as_int(ledger.get("height"), 0),
                "readiness_expires_height": int(readiness["readiness_expires_height"]),
            }
        )
    else:
        validator.update({"active": False, "readiness_status": "failed", "readiness_failed_at_nonce": int(env.nonce), "readiness_failed_at_height": _as_int(ledger.get("height"), 0)})
    responsibilities["validator"] = validator
    by_id[acct] = rec
    return {"applied": "VALIDATOR_READINESS_VERIFY", "account_id": acct, "verified": status in ("verified", "ready")}


def _require_system_env(env: TxEnvelope) -> None:
    if bool(getattr(env, "system", False)) or _as_str(getattr(env, "signer", "")) == "SYSTEM":
        return
    raise RolesApplyError(
        "forbidden", "system_tx_required", {"tx_type": env.tx_type, "signer": env.signer}
    )


PROTOCOL_TREASURY_ID = "TREASURY_PROTOCOL"


def _sync_protocol_treasury_from_emissaries(ledger: Json, *, reason: str, nonce: int) -> None:
    """Keep the protocol treasury signer set in lockstep with the seated emissary set.

    Design goals:
      - One global protocol treasury exists from genesis.
      - It is emissary-controlled (require_emissary_signers=true).
      - Signers should automatically become the currently seated emissaries.
      - Enforce multisig semantics: do not enable (set signers/threshold) until at least 2 emissaries are seated.
      - Preserve the configured threshold where possible, but never exceed signer count and never drop below 2.
    """
    roles = _ensure_roles(ledger)
    treasuries = roles.get("treasuries_by_id")
    if not isinstance(treasuries, dict):
        return

    obj = treasuries.get(PROTOCOL_TREASURY_ID)
    if not isinstance(obj, dict):
        return

    # Only sync if this treasury is explicitly emissary-controlled.
    if not bool(obj.get("require_emissary_signers", False)):
        return

    # Allow opting out of auto-sync in genesis or via governance/system maintenance.
    if obj.get("auto_sync_emissaries", True) is False:
        return

    em = roles.get("emissaries")
    seated: list[str] = []
    if isinstance(em, dict) and isinstance(em.get("seated"), list):
        seated = [str(x).strip() for x in em.get("seated") if str(x).strip()]
    seated = sorted(set([s for s in seated if s]))

    # Keep the treasury inert until we have at least 2 emissaries (multisig semantics).
    # Important removal hardening: if the seated set falls below quorum after a
    # ROLE_EMISSARY_REMOVE, do not leave stale removed emissaries in the signer
    # snapshot.  Clear signers and preserve a threshold of 2 so the treasury is
    # visibly inert until governance seats enough emissaries again.
    if len(seated) < 2:
        existing_signers = obj.get("signers")
        existing_signers = (
            sorted(set([str(x).strip() for x in existing_signers if str(x).strip()]))
            if isinstance(existing_signers, list)
            else []
        )
        if existing_signers or _as_int(obj.get("threshold"), 2) != 2:
            set_treasury_signers(ledger, PROTOCOL_TREASURY_ID, [], threshold=2)
            treasuries = roles.get("treasuries_by_id")
            obj2 = treasuries.get(PROTOCOL_TREASURY_ID) if isinstance(treasuries, dict) else None
            if isinstance(obj2, dict):
                obj2["require_emissary_signers"] = True
                obj2.setdefault("label", "protocol")
                obj2.setdefault("auto_sync_emissaries", True)
                obj2["updated_at_nonce"] = int(nonce)
                obj2["synced_from_emissaries_at_nonce"] = int(nonce)
                obj2["synced_from_emissaries_reason"] = f"{reason}:inert_until_two_emissaries"
                treasuries[PROTOCOL_TREASURY_ID] = obj2
        return

    existing_signers = obj.get("signers")
    existing_signers = (
        sorted(set([str(x).strip() for x in existing_signers if str(x).strip()]))
        if isinstance(existing_signers, list)
        else []
    )
    existing_threshold = _as_int(obj.get("threshold"), 2)
    if existing_threshold < 2:
        existing_threshold = 2

    desired_threshold = min(max(2, existing_threshold), len(seated))

    # No-op if already synced.
    if (
        existing_signers == seated
        and _as_int(obj.get("threshold"), desired_threshold) == desired_threshold
    ):
        return

    # Normalize via schema helper then re-attach metadata.
    set_treasury_signers(ledger, PROTOCOL_TREASURY_ID, seated, threshold=desired_threshold)

    treasuries = roles.get("treasuries_by_id")
    obj2 = treasuries.get(PROTOCOL_TREASURY_ID) if isinstance(treasuries, dict) else None
    if isinstance(obj2, dict):
        obj2["require_emissary_signers"] = True
        obj2.setdefault("label", "protocol")
        obj2.setdefault("auto_sync_emissaries", True)
        obj2["updated_at_nonce"] = int(nonce)
        obj2["synced_from_emissaries_at_nonce"] = int(nonce)
        obj2["synced_from_emissaries_reason"] = str(reason)
        treasuries[PROTOCOL_TREASURY_ID] = obj2


# ---------------------------------------------------------------------------
# Jurors role
# ---------------------------------------------------------------------------


def _apply_role_juror_enroll(ledger: Json, env: TxEnvelope) -> Json:
    roles = _ensure_roles(ledger)
    jur = roles.get("jurors")
    if not isinstance(jur, dict):
        jur = {"by_id": {}, "active_set": []}
        roles["jurors"] = jur

    payload = _as_dict(env.payload)
    acct = _pick_account(payload, "account_id", "juror", "target", "account")
    if not acct:
        raise RolesApplyError("invalid_payload", "missing_account_id", {"tx_type": env.tx_type})
    if acct != env.signer:
        raise RolesApplyError("forbidden", "only_account_can_enroll_juror", {"account_id": acct})

    by_id = jur.get("by_id")
    if not isinstance(by_id, dict):
        by_id = {}
        jur["by_id"] = by_id

    rec = _touch(by_id, acct)
    had = bool(rec.get("enrolled", False))
    rec["enrolled"] = True
    rec["enrolled_at_nonce"] = int(env.nonce)
    by_id[acct] = rec

    jur["by_id"] = by_id
    return {"applied": "ROLE_JUROR_ENROLL", "account_id": acct, "deduped": had}


def _apply_role_juror_activate(ledger: Json, env: TxEnvelope) -> Json:
    roles = _ensure_roles(ledger)
    jur = roles.get("jurors")
    if not isinstance(jur, dict):
        jur = {"by_id": {}, "active_set": []}
        roles["jurors"] = jur

    payload = _as_dict(env.payload)
    acct = _pick_account(payload, "account_id", "juror", "target", "account")
    if not acct:
        raise RolesApplyError("invalid_payload", "missing_account_id", {"tx_type": env.tx_type})

    by_id = jur.get("by_id")
    if not isinstance(by_id, dict):
        by_id = {}
        jur["by_id"] = by_id

    rec = _touch(by_id, acct)
    if not bool(rec.get("enrolled", False)):
        raise RolesApplyError("not_found", "juror_not_enrolled", {"account_id": acct})
    _require_role_activation_eligible(
        ledger,
        acct,
        role="juror",
        minimum_reputation_milli=_role_required_reputation_milli(ledger, payload, "juror", 0),
    )

    rec["active"] = True
    rec["activated_at_nonce"] = int(env.nonce)
    _ensure_node_operator_responsibilities(rec)
    by_id[acct] = rec
    jur["by_id"] = by_id

    aset = jur.get("active_set")
    if not isinstance(aset, list):
        aset = []
    had = acct in aset
    if not had:
        aset = sorted({*(str(x) for x in aset if str(x).strip()), acct})
    jur["active_set"] = aset
    return {"applied": "ROLE_JUROR_ACTIVATE", "account_id": acct, "deduped": had}


def _apply_role_juror_suspend(ledger: Json, env: TxEnvelope) -> Json:
    roles = _ensure_roles(ledger)
    jur = roles.get("jurors")
    if not isinstance(jur, dict):
        jur = {"by_id": {}, "active_set": []}
        roles["jurors"] = jur

    payload = _as_dict(env.payload)
    acct = _pick_account(payload, "account_id", "juror", "target", "account")
    if not acct:
        raise RolesApplyError("invalid_payload", "missing_account_id", {"tx_type": env.tx_type})

    by_id = jur.get("by_id")
    if not isinstance(by_id, dict):
        by_id = {}
        jur["by_id"] = by_id

    rec = _touch(by_id, acct)
    if not bool(rec.get("enrolled", False)):
        raise RolesApplyError("not_found", "juror_not_enrolled", {"account_id": acct})

    already = not bool(rec.get("active", False))
    rec["active"] = False
    rec["suspended_at_nonce"] = int(env.nonce)
    by_id[acct] = rec
    jur["by_id"] = by_id

    aset = jur.get("active_set")
    if not isinstance(aset, list):
        aset = []
    if acct in aset:
        aset = sorted([a for a in aset if a != acct])
    jur["active_set"] = aset
    return {"applied": "ROLE_JUROR_SUSPEND", "account_id": acct, "deduped": already}


def _apply_role_juror_reinstate(ledger: Json, env: TxEnvelope) -> Json:
    # Alias for activate in MVP
    return _apply_role_juror_activate(ledger, env)


# ---------------------------------------------------------------------------
# Validators role
# ---------------------------------------------------------------------------


def _apply_role_validator_activate(ledger: Json, env: TxEnvelope) -> Json:
    _require_system_env(env)
    roles = _ensure_roles(ledger)
    validators = roles.get("validators")
    if not isinstance(validators, dict):
        validators = {"active_set": []}
        roles["validators"] = validators

    payload = _as_dict(env.payload)
    acct = _pick_account(payload, "account_id", "validator", "target", "account")
    if not acct:
        raise RolesApplyError("invalid_payload", "missing_account_id", {"tx_type": env.tx_type})

    _require_role_activation_eligible(
        ledger,
        acct,
        role="validator",
        minimum_reputation_milli=_role_required_reputation_milli(ledger, payload, "validator", 5000),
    )

    if not is_node_operator_active(ledger, acct):
        raise RolesApplyError("forbidden", "node_operator_status_required", {"account_id": acct})

    ops = _as_dict(roles.get("node_operators"))
    by_id = _as_dict(ops.get("by_id"))
    op_rec = _as_dict(by_id.get(acct))
    responsibilities = _as_dict(op_rec.get("responsibilities"))
    validator_resp = _as_dict(responsibilities.get("validator"))
    if not bool(validator_resp.get("active", False)) or _as_str(validator_resp.get("readiness_status")).strip().lower() not in {"verified", "ready"}:
        raise RolesApplyError("forbidden", "validator_readiness_required", {"account_id": acct})

    expires_height = _as_int(validator_resp.get("readiness_expires_height"), 0)
    current_height = _as_int(ledger.get("height"), 0)
    if expires_height > 0 and current_height > expires_height:
        raise RolesApplyError(
            "forbidden",
            "validator_readiness_expired",
            {"account_id": acct, "current_height": current_height, "expires_height": expires_height},
        )

    node_pubkey = _as_str(payload.get("node_pubkey") or payload.get("node_public_key") or validator_resp.get("node_pubkey")).strip()
    if node_pubkey and node_pubkey not in _active_node_pubkeys_for_account(ledger, acct):
        raise RolesApplyError("forbidden", "node_key_not_registered", {"account_id": acct})

    aset = validators.get("active_set")
    if not isinstance(aset, list):
        aset = []
    had = acct in aset
    if not had:
        aset = sorted({*(str(x) for x in aset if str(x).strip()), acct})
    validators["active_set"] = aset
    validators.setdefault("by_id", {})
    if isinstance(validators.get("by_id"), dict):
        rec = _touch(validators["by_id"], acct)
        rec["active"] = True
        rec["activated_at_nonce"] = int(env.nonce)
        rec["node_pubkey"] = node_pubkey or rec.get("node_pubkey", "")
        rec["readiness_receipt_hash"] = validator_resp.get("readiness_receipt_hash")
        validators["by_id"][acct] = rec
    roles["validators"] = validators
    return {"applied": "ROLE_VALIDATOR_ACTIVATE", "account_id": acct, "deduped": had}


def _apply_role_validator_suspend(ledger: Json, env: TxEnvelope) -> Json:
    roles = _ensure_roles(ledger)
    validators = roles.get("validators")
    if not isinstance(validators, dict):
        validators = {"active_set": []}
        roles["validators"] = validators

    payload = _as_dict(env.payload)
    acct = _pick_account(payload, "account_id", "validator", "target", "account")
    if not acct:
        raise RolesApplyError("invalid_payload", "missing_account_id", {"tx_type": env.tx_type})

    aset = validators.get("active_set")
    if not isinstance(aset, list):
        aset = []
    already = acct not in aset
    if acct in aset:
        aset = sorted([a for a in aset if a != acct])
    validators["active_set"] = aset
    roles["validators"] = validators
    return {"applied": "ROLE_VALIDATOR_SUSPEND", "account_id": acct, "deduped": already}


# ---------------------------------------------------------------------------
# Node Operators role
# ---------------------------------------------------------------------------


def _apply_role_node_operator_enroll(ledger: Json, env: TxEnvelope) -> Json:
    roles = _ensure_roles(ledger)
    ops = roles.get("node_operators")
    if not isinstance(ops, dict):
        ops = {"by_id": {}, "active_set": []}
        roles["node_operators"] = ops

    payload = _as_dict(env.payload)
    acct = _pick_account(payload, "account_id", "operator", "node_operator", "target", "account")
    if not acct:
        raise RolesApplyError("invalid_payload", "missing_account_id", {"tx_type": env.tx_type})
    if acct != env.signer:
        raise RolesApplyError("forbidden", "only_account_can_enroll_node_operator", {"account_id": acct})

    by_id = ops.get("by_id")
    if not isinstance(by_id, dict):
        by_id = {}
        ops["by_id"] = by_id

    rec = _touch(by_id, acct)
    had = bool(rec.get("enrolled", False))
    rec["enrolled"] = True
    rec["enrolled_at_nonce"] = int(env.nonce)
    validator_opted_in = False
    if _has_validator_responsibility_intent(payload):
        _apply_node_validator_responsibility_opt_in(
            ledger,
            ops=ops,
            acct=acct,
            rec=rec,
            payload=payload,
            nonce=int(env.nonce),
        )
        validator_opted_in = True

    storage_opted_in = False
    if _has_storage_responsibility_intent(payload):
        _apply_node_storage_responsibility_opt_in(
            ledger,
            ops=ops,
            acct=acct,
            rec=rec,
            payload=payload,
            nonce=int(env.nonce),
        )
        storage_opted_in = True
    by_id[acct] = rec

    ops["by_id"] = by_id
    return {
        "applied": "ROLE_NODE_OPERATOR_ENROLL",
        "account_id": acct,
        "deduped": had,
        "validator_opted_in": validator_opted_in,
        "storage_opted_in": storage_opted_in,
    }


def _apply_role_node_operator_activate(ledger: Json, env: TxEnvelope) -> Json:
    _require_system_env(env)
    roles = _ensure_roles(ledger)
    ops = roles.get("node_operators")
    if not isinstance(ops, dict):
        ops = {"by_id": {}, "active_set": []}
        roles["node_operators"] = ops

    payload = _as_dict(env.payload)
    acct = _pick_account(payload, "account_id", "operator", "node_operator", "target", "account")
    if not acct:
        raise RolesApplyError("invalid_payload", "missing_account_id", {"tx_type": env.tx_type})

    by_id = ops.get("by_id")
    if not isinstance(by_id, dict):
        by_id = {}
        ops["by_id"] = by_id

    rec = _touch(by_id, acct)
    if not bool(rec.get("enrolled", False)):
        raise RolesApplyError("not_found", "node_operator_not_enrolled", {"account_id": acct})
    _require_role_activation_eligible(
        ledger,
        acct,
        role="node_operator",
        minimum_reputation_milli=_role_required_reputation_milli(ledger, payload, "node_operator", 0),
    )

    rec["active"] = True
    rec["activated_at_nonce"] = int(env.nonce)
    _ensure_node_operator_responsibilities(rec)
    by_id[acct] = rec
    ops["by_id"] = by_id

    aset = ops.get("active_set")
    if not isinstance(aset, list):
        aset = []
    had = acct in aset
    if not had:
        aset = sorted({*(str(x) for x in aset if str(x).strip()), acct})
    ops["active_set"] = aset
    return {"applied": "ROLE_NODE_OPERATOR_ACTIVATE", "account_id": acct, "deduped": had}


def _apply_role_node_operator_suspend(ledger: Json, env: TxEnvelope) -> Json:
    roles = _ensure_roles(ledger)
    ops = roles.get("node_operators")
    if not isinstance(ops, dict):
        ops = {"by_id": {}, "active_set": []}
        roles["node_operators"] = ops

    payload = _as_dict(env.payload)
    acct = _pick_account(payload, "account_id", "operator", "node_operator", "target", "account")
    if not acct:
        raise RolesApplyError("invalid_payload", "missing_account_id", {"tx_type": env.tx_type})

    by_id = ops.get("by_id")
    if not isinstance(by_id, dict):
        by_id = {}
        ops["by_id"] = by_id

    rec = _touch(by_id, acct)
    if not bool(rec.get("enrolled", False)):
        raise RolesApplyError("not_found", "node_operator_not_enrolled", {"account_id": acct})

    already = not bool(rec.get("active", False))
    rec["active"] = False
    rec["suspended_at_nonce"] = int(env.nonce)
    by_id[acct] = rec
    ops["by_id"] = by_id

    aset = ops.get("active_set")
    if not isinstance(aset, list):
        aset = []
    if acct in aset:
        aset = sorted([a for a in aset if a != acct])
    ops["active_set"] = aset
    return {"applied": "ROLE_NODE_OPERATOR_SUSPEND", "account_id": acct, "deduped": already}


# ---------------------------------------------------------------------------
# Emissaries role (nominate/vote/seat/remove)
# ---------------------------------------------------------------------------


def _apply_role_emissary_nominate(ledger: Json, env: TxEnvelope) -> Json:
    roles = _ensure_roles(ledger)
    em = roles.get("emissaries")
    if not isinstance(em, dict):
        em = {"by_id": {}, "nominations": {}, "seated": []}
        roles["emissaries"] = em

    payload = _as_dict(env.payload)
    target = _pick_account(payload, "account_id", "emissary", "target", "account")
    if not target:
        raise RolesApplyError("invalid_payload", "missing_account_id", {"tx_type": env.tx_type})

    noms = em.get("nominations")
    if not isinstance(noms, dict):
        noms = {}
        em["nominations"] = noms

    nom = noms.get(target)
    if not isinstance(nom, dict):
        nom = {"account_id": target, "votes": [], "created_at_nonce": int(env.nonce)}
    votes = nom.get("votes")
    if not isinstance(votes, list):
        votes = []
    # nominee auto-vote by nominator
    if env.signer not in votes:
        votes.append(env.signer)
    nom["votes"] = votes
    noms[target] = nom
    em["nominations"] = noms

    return {"applied": "ROLE_EMISSARY_NOMINATE", "account_id": target}


def _apply_role_emissary_vote(ledger: Json, env: TxEnvelope) -> Json:
    roles = _ensure_roles(ledger)
    em = roles.get("emissaries")
    if not isinstance(em, dict):
        em = {"by_id": {}, "nominations": {}, "seated": []}
        roles["emissaries"] = em

    payload = _as_dict(env.payload)
    target = _pick_account(payload, "account_id", "emissary", "target", "account")
    if not target:
        raise RolesApplyError("invalid_payload", "missing_account_id", {"tx_type": env.tx_type})

    noms = em.get("nominations")
    if not isinstance(noms, dict):
        raise RolesApplyError("not_found", "no_nominations", {})

    nom = noms.get(target)
    if not isinstance(nom, dict):
        raise RolesApplyError("not_found", "nomination_not_found", {"account_id": target})

    votes = nom.get("votes")
    if not isinstance(votes, list):
        votes = []
    had = env.signer in votes
    if not had:
        votes.append(env.signer)
    nom["votes"] = votes
    noms[target] = nom
    em["nominations"] = noms

    return {"applied": "ROLE_EMISSARY_VOTE", "account_id": target, "deduped": had}


def _apply_role_emissary_seat(ledger: Json, env: TxEnvelope) -> Json:
    # This is a system action in many designs; keep permissive unless canon forbids.
    roles = _ensure_roles(ledger)
    em = roles.get("emissaries")
    if not isinstance(em, dict):
        em = {"by_id": {}, "nominations": {}, "seated": []}
        roles["emissaries"] = em

    payload = _as_dict(env.payload)
    acct = _pick_account(payload, "account_id", "emissary", "target", "account")
    if not acct:
        raise RolesApplyError("invalid_payload", "missing_account_id", {"tx_type": env.tx_type})
    _require_role_activation_eligible(
        ledger,
        acct,
        role="emissary",
        minimum_reputation_milli=_role_required_reputation_milli(ledger, payload, "emissary", 0),
    )

    by_id = em.get("by_id")
    if not isinstance(by_id, dict):
        by_id = {}
        em["by_id"] = by_id

    rec = _touch(by_id, acct)
    had = bool(rec.get("active", False))
    rec["active"] = True
    rec["seated_at_nonce"] = int(env.nonce)
    by_id[acct] = rec

    seated = em.get("seated")
    if not isinstance(seated, list):
        seated = []
    if acct not in seated:
        seated = sorted({*(str(x) for x in seated if str(x).strip()), acct})
    em["seated"] = seated
    _sync_protocol_treasury_from_emissaries(ledger, reason="emissary_seated", nonce=int(env.nonce))
    return {"applied": "ROLE_EMISSARY_SEAT", "account_id": acct, "deduped": had}


def _apply_role_emissary_remove(ledger: Json, env: TxEnvelope) -> Json:
    roles = _ensure_roles(ledger)
    em = roles.get("emissaries")
    if not isinstance(em, dict):
        em = {"by_id": {}, "nominations": {}, "seated": []}
        roles["emissaries"] = em

    payload = _as_dict(env.payload)
    acct = _pick_account(payload, "account_id", "emissary", "target", "account")
    if not acct:
        raise RolesApplyError("invalid_payload", "missing_account_id", {"tx_type": env.tx_type})

    by_id = em.get("by_id")
    if not isinstance(by_id, dict):
        by_id = {}
        em["by_id"] = by_id

    rec = _touch(by_id, acct)
    had = bool(rec.get("active", False))
    rec["active"] = False
    rec["removed"] = True
    rec["removed_at_nonce"] = int(env.nonce)
    if isinstance(payload.get("reason"), str):
        rec["remove_reason"] = payload.get("reason")
    by_id[acct] = rec

    seated = em.get("seated")
    if not isinstance(seated, list):
        seated = []
    if acct in seated:
        seated = sorted([a for a in seated if a != acct])
    em["seated"] = seated
    _sync_protocol_treasury_from_emissaries(ledger, reason="emissary_removed", nonce=int(env.nonce))
    return {"applied": "ROLE_EMISSARY_REMOVE", "account_id": acct, "deduped": (not had)}


# ---------------------------------------------------------------------------
# Gov Executor role pointer
# ---------------------------------------------------------------------------


def _apply_role_gov_executor_set(ledger: Json, env: TxEnvelope) -> Json:
    _require_system_env(env)
    roles = _ensure_roles(ledger)
    gov_exec = roles.get("gov_executor")
    if not isinstance(gov_exec, dict):
        gov_exec = {"current": "", "active": True}
        roles["gov_executor"] = gov_exec

    payload = _as_dict(env.payload)
    acct = _pick_account(payload, "account_id", "executor", "target", "account", "gov_executor")
    if not acct:
        raise RolesApplyError("invalid_payload", "missing_account_id", {"tx_type": env.tx_type})
    _require_role_activation_eligible(
        ledger,
        acct,
        role="gov_executor",
        minimum_reputation_milli=_role_required_reputation_milli(ledger, payload, "gov_executor", 0),
    )

    already = _as_str(gov_exec.get("current")).strip() == acct and bool(
        gov_exec.get("active", True)
    )
    gov_exec["current"] = acct
    gov_exec["active"] = True
    gov_exec["set_at_nonce"] = int(env.nonce)
    if isinstance(payload.get("note"), str):
        gov_exec["note"] = payload.get("note")
    roles["gov_executor"] = gov_exec

    return {"applied": "ROLE_GOV_EXECUTOR_SET", "account_id": acct, "deduped": already}


# ---------------------------------------------------------------------------
# MVP Treasury role authority (TREASURY_CREATE / TREASURY_SIGNERS_SET)
# ---------------------------------------------------------------------------


def _apply_treasury_create(ledger: Json, env: TxEnvelope) -> Json:
    roles = _ensure_roles(ledger)
    payload = _as_dict(env.payload)

    treasury_id = _as_str(payload.get("treasury_id") or payload.get("id")).strip()
    if not treasury_id:
        raise RolesApplyError("invalid_payload", "missing_treasury_id", {"tx_type": env.tx_type})

    treasuries = roles.get("treasuries_by_id")
    if not isinstance(treasuries, dict):
        treasuries = {}
        roles["treasuries_by_id"] = treasuries

    if treasury_id in treasuries:
        raise RolesApplyError("duplicate", "treasury_id_exists", {"treasury_id": treasury_id})

    # Default signer set = creator, threshold=1
    is_system = (
        bool(getattr(env, "system", False))
        or str(getattr(env, "signer", "") or "").strip() == "SYSTEM"
    )

    treasuries[treasury_id] = {
        "signers": [env.signer],
        "threshold": 2 if is_system else 1,
        "created_by": env.signer,
        "created_at_nonce": int(env.nonce),
        # Protocol treasuries are expected to be controlled by seated emissaries.
        # For system-created treasuries, default to requiring emissary signers.
        "require_emissary_signers": bool(is_system),
    }
    roles["treasuries_by_id"] = treasuries
    return {"applied": "TREASURY_CREATE", "treasury_id": treasury_id}


def _apply_treasury_signers_set(ledger: Json, env: TxEnvelope) -> Json:
    roles = _ensure_roles(ledger)
    payload = _as_dict(env.payload)

    treasury_id = _as_str(payload.get("treasury_id") or payload.get("id")).strip()
    if not treasury_id:
        raise RolesApplyError("invalid_payload", "missing_treasury_id", {"tx_type": env.tx_type})

    treasuries = roles.get("treasuries_by_id")
    if not isinstance(treasuries, dict) or not isinstance(treasuries.get(treasury_id), dict):
        raise RolesApplyError("not_found", "treasury_not_found", {"treasury_id": treasury_id})

    t_obj = treasuries.get(treasury_id)
    require_emissary = (
        bool(t_obj.get("require_emissary_signers", False)) if isinstance(t_obj, dict) else False
    )

    signers = [s for s in _as_list(payload.get("signers")) if isinstance(s, str) and s.strip()]
    # deterministic uniq sort
    signers = sorted(set([s.strip() for s in signers if s.strip()]))

    if not signers:
        raise RolesApplyError("invalid_payload", "missing_signers", {"treasury_id": treasury_id})

    threshold = _as_int(payload.get("threshold"), 1)
    if threshold <= 0:
        threshold = 1

    # If this treasury is flagged as emissary-controlled, enforce that the signer
    # set is a subset of currently seated emissaries and that threshold is at least 2.
    if require_emissary:
        em = roles.get("emissaries")
        seated = []
        if isinstance(em, dict) and isinstance(em.get("seated"), list):
            seated = [str(x).strip() for x in em.get("seated") if str(x).strip()]
        seated_set = set(seated)
        bad = [s for s in signers if s not in seated_set]
        if bad:
            raise RolesApplyError(
                "forbidden",
                "treasury_signers_must_be_seated_emissaries",
                {"treasury_id": treasury_id, "bad_signers": bad},
            )
        if threshold < 2:
            threshold = 2
    if threshold > len(signers):
        raise RolesApplyError(
            "bad_payload",
            "threshold_exceeds_signers",
            {"treasury_id": treasury_id, "threshold": threshold, "n_signers": len(signers)},
        )

    active_spend = _active_protocol_treasury_spend_for_treasury(ledger, treasury_id)
    if isinstance(active_spend, dict):
        raise RolesApplyError(
            "forbidden",
            "treasury_spend_open",
            {
                "treasury_id": treasury_id,
                "spend_id": _as_str(active_spend.get("spend_id")).strip(),
                "status": _as_str(active_spend.get("status")).strip().lower() or "proposed",
            },
        )

    # Use schema helper to normalize
    set_treasury_signers(ledger, treasury_id, signers, threshold=threshold)

    # Preserve metadata
    treasuries = roles.get("treasuries_by_id")
    obj = treasuries.get(treasury_id) if isinstance(treasuries, dict) else None
    if isinstance(obj, dict):
        obj["updated_at_nonce"] = int(env.nonce)
        treasuries[treasury_id] = obj

    return {
        "applied": "TREASURY_SIGNERS_SET",
        "treasury_id": treasury_id,
        "threshold": threshold,
        "n_signers": len(signers),
    }




def _active_protocol_treasury_spend_for_treasury(ledger: Json, treasury_id: str) -> Json | None:
    tre = ledger.get("treasury")
    if not isinstance(tre, dict):
        return None
    spends = tre.get("spends")
    if not isinstance(spends, dict):
        return None
    tid = _as_str(treasury_id).strip()
    for spend in spends.values():
        if not isinstance(spend, dict):
            continue
        if _as_str(spend.get("treasury_id")).strip() != tid:
            continue
        status = _as_str(spend.get("status")).strip().lower()
        if status in ("executed", "canceled", "cancelled", "expired"):
            continue
        return spend
    return None

# ---------------------------------------------------------------------------
# Router
# ---------------------------------------------------------------------------

ROLES_TX_TYPES: set[str] = {
    "ROLE_JUROR_ENROLL",
    "ROLE_JUROR_ACTIVATE",
    "ROLE_JUROR_SUSPEND",
    "ROLE_JUROR_REINSTATE",
    "ROLE_VALIDATOR_ACTIVATE",
    "ROLE_VALIDATOR_SUSPEND",
    "ROLE_NODE_OPERATOR_ENROLL",
    "ROLE_NODE_OPERATOR_ACTIVATE",
    "ROLE_NODE_OPERATOR_SUSPEND",
    "NODE_OPERATOR_STORAGE_OPT_IN",
    "NODE_OPERATOR_VALIDATOR_OPT_IN",
    "NODE_OPERATOR_RESPONSIBILITY_UPDATE",
    "VALIDATOR_READINESS_VERIFY",
    "ROLE_EMISSARY_NOMINATE",
    "ROLE_EMISSARY_VOTE",
    "ROLE_EMISSARY_SEAT",
    "ROLE_EMISSARY_REMOVE",
    "ROLE_GOV_EXECUTOR_SET",
    "TREASURY_CREATE",
    "TREASURY_SIGNERS_SET",
}


def apply_roles(ledger: Json, env: TxEnvelope) -> Json | None:
    t = _as_str(env.tx_type).strip().upper()
    if t not in ROLES_TX_TYPES:
        return None

    if t == "ROLE_JUROR_ENROLL":
        return _apply_role_juror_enroll(ledger, env)
    if t == "ROLE_JUROR_ACTIVATE":
        return _apply_role_juror_activate(ledger, env)
    if t == "ROLE_JUROR_SUSPEND":
        return _apply_role_juror_suspend(ledger, env)
    if t == "ROLE_JUROR_REINSTATE":
        return _apply_role_juror_reinstate(ledger, env)

    if t == "ROLE_VALIDATOR_ACTIVATE":
        return _apply_role_validator_activate(ledger, env)
    if t == "ROLE_VALIDATOR_SUSPEND":
        return _apply_role_validator_suspend(ledger, env)

    if t == "ROLE_NODE_OPERATOR_ENROLL":
        return _apply_role_node_operator_enroll(ledger, env)
    if t == "ROLE_NODE_OPERATOR_ACTIVATE":
        return _apply_role_node_operator_activate(ledger, env)
    if t == "ROLE_NODE_OPERATOR_SUSPEND":
        return _apply_role_node_operator_suspend(ledger, env)
    if t == "NODE_OPERATOR_STORAGE_OPT_IN":
        return _apply_node_operator_storage_opt_in_tx(ledger, env)
    if t == "NODE_OPERATOR_VALIDATOR_OPT_IN":
        return _apply_node_operator_validator_opt_in_tx(ledger, env)
    if t == "NODE_OPERATOR_RESPONSIBILITY_UPDATE":
        return _apply_node_operator_responsibility_update(ledger, env)
    if t == "VALIDATOR_READINESS_VERIFY":
        return _apply_validator_readiness_verify(ledger, env)

    if t == "ROLE_EMISSARY_NOMINATE":
        return _apply_role_emissary_nominate(ledger, env)
    if t == "ROLE_EMISSARY_VOTE":
        return _apply_role_emissary_vote(ledger, env)
    if t == "ROLE_EMISSARY_SEAT":
        return _apply_role_emissary_seat(ledger, env)
    if t == "ROLE_EMISSARY_REMOVE":
        return _apply_role_emissary_remove(ledger, env)

    if t == "ROLE_GOV_EXECUTOR_SET":
        return _apply_role_gov_executor_set(ledger, env)

    if t == "TREASURY_CREATE":
        return _apply_treasury_create(ledger, env)
    if t == "TREASURY_SIGNERS_SET":
        return _apply_treasury_signers_set(ledger, env)

    return None


__all__ = ["ROLES_TX_TYPES", "RolesApplyError", "apply_roles"]
