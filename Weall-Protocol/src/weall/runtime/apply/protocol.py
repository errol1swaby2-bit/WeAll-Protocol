from __future__ import annotations

"""weall.runtime.apply.protocol

Protocol-upgrade domain apply semantics.

Canon txs (v2.x):
  - PROTOCOL_UPGRADE_DECLARE  (SYSTEM, block, receipt_only, parent=GOV_EXECUTE)
  - PROTOCOL_UPGRADE_ACTIVATE (SYSTEM, block, receipt_only, parent=PROTOCOL_UPGRADE_DECLARE)

This module is intentionally minimal, deterministic, and safety bounded:
  - It records declared upgrades (append/overwrite by upgrade_id)
  - It records governance-approved activation intent at a deterministic future height
  - It does not perform migrations; it only records state for auditing/UI.

State surface:
state["protocol"] = {
  "upgrades": {
     upgrade_id: {
        "upgrade_id": str,
        "version": str|None,
        "hash": str|None,
        "status": "declared"|"scheduled"|"effective",
        "declared_at_height": int,
        "declared_at_nonce": int,
        "activation_height": int|None,
        "governance_approved_at_height": int|None,
        "governance_approved_at_nonce": int|None,
        "parent": str|None,
        "payload": {...},
     },
  },
  "active": {
     "upgrade_id": str|None,
     "version": str|None,
     "hash": str|None,
     "activation_height": int,
     "governance_approved_at_height": int,
     "governance_approved_at_nonce": int,
  }
}

Notes:
- Parent constraints + receipt_only are enforced at admission/router level.
- We still enforce env.system=True for defense-in-depth.
- Automatic software apply/migration/rollback remains disabled.  Activation here
  means a public, governance-approved compatibility record at a deterministic
  block height, not an instruction to mutate node binaries or private operator
  machines.
"""

from dataclasses import dataclass
from typing import Any

from weall.runtime.tx_admission import TxEnvelope

Json = dict[str, Any]


@dataclass
class ProtocolApplyError(RuntimeError):
    code: str
    reason: str
    details: Json

    def __str__(self) -> str:
        return f"{self.code}:{self.reason}:{self.details}"


def _as_dict(x: Any) -> Json:
    return x if isinstance(x, dict) else {}


def _as_str(x: Any) -> str:
    return x if isinstance(x, str) else ""


def _as_int(x: Any, default: int = 0) -> int:
    try:
        return int(x)
    except Exception:
        return int(default)


def _require_system_env(env: TxEnvelope) -> None:
    if not bool(getattr(env, "system", False)):
        raise ProtocolApplyError("forbidden", "system_only", {"tx_type": env.tx_type})


def _parent_ref(env: TxEnvelope) -> str:
    payload = _as_dict(getattr(env, "payload", None))
    return _as_str(getattr(env, "parent", None)).strip() or _as_str(payload.get("_parent_ref")).strip()


def _require_parent_ref(env: TxEnvelope) -> str:
    ref = _parent_ref(env)
    if not ref:
        raise ProtocolApplyError(
            "forbidden",
            "protocol_upgrade_requires_governance_parent",
            {
                "tx_type": env.tx_type,
                "required_boundary": "SYSTEM queue / receipt-only parent reference",
            },
        )
    return ref


def _ensure_root_dict(state: Json, key: str) -> Json:
    cur = state.get(key)
    if not isinstance(cur, dict):
        cur = {}
        state[key] = cur
    return cur


def _ensure_protocol(state: Json) -> Json:
    p = _ensure_root_dict(state, "protocol")
    if not isinstance(p.get("upgrades"), dict):
        p["upgrades"] = {}
    if "active" in p and not isinstance(p.get("active"), dict):
        p["active"] = {}
    return p


def _height_now(state: Json, env: TxEnvelope | None = None) -> int:
    payload = _as_dict(getattr(env, "payload", None)) if env is not None else {}
    due_height = _as_int(payload.get("_due_height"), 0)
    if due_height > 0:
        return int(due_height)
    return _as_int(state.get("height"), 0) + 1


DEFAULT_UPGRADE_ACTIVATION_DELAY_BLOCKS = 30


def _activation_delay_blocks(state: Json, payload: Json) -> int:
    raw = payload.get("activation_delay_blocks")
    if raw is None:
        proto = _as_dict(state.get("protocol"))
        raw = proto.get("default_upgrade_activation_delay_blocks")
    delay = _as_int(raw, DEFAULT_UPGRADE_ACTIVATION_DELAY_BLOCKS)
    return max(1, delay)


def _requested_activation_height(state: Json, payload: Json, env: TxEnvelope | None = None) -> int:
    current_height = _height_now(state, env)
    explicit = _as_int(payload.get("activation_height"), 0)
    if explicit > 0:
        return explicit
    return current_height + _activation_delay_blocks(state, payload)


def _validate_activation_height(state: Json, payload: Json, *, upgrade_id: str, env: TxEnvelope | None = None) -> int:
    activation_height = _requested_activation_height(state, payload, env)
    current_height = _height_now(state, env)
    if activation_height <= current_height:
        raise ProtocolApplyError(
            "forbidden",
            "upgrade_activation_height_must_be_future",
            {
                "upgrade_id": upgrade_id,
                "activation_height": int(activation_height),
                "current_height": int(current_height),
            },
        )
    return int(activation_height)


def _target_version(payload: Json) -> str:
    return (
        _as_str(payload.get("version")).strip()
        or _as_str(payload.get("target_version")).strip()
        or _as_str(payload.get("rule_target")).strip()
        or _as_str(payload.get("target")).strip()
    )


def _configured_supported_targets(state: Json) -> set[str]:
    proto = _as_dict(state.get("protocol"))
    meta = _as_dict(state.get("meta"))
    raw = proto.get("supported_upgrade_targets")
    if raw is None:
        raw = meta.get("supported_upgrade_targets")
    if raw is None:
        raw = meta.get("supported_protocol_versions")
    if not isinstance(raw, list):
        return set()
    return {str(item).strip() for item in raw if str(item).strip()}


def _validate_target_supported(state: Json, *, target_version: str, upgrade_id: str) -> Json:
    supported = _configured_supported_targets(state)
    if supported and target_version not in supported:
        raise ProtocolApplyError(
            "forbidden",
            "unsupported_protocol_upgrade_target",
            {
                "upgrade_id": upgrade_id,
                "target_version": target_version,
                "supported_upgrade_targets": sorted(supported),
            },
        )
    return {
        "target_version": target_version,
        "supported_targets_configured": bool(supported),
        "target_supported_by_local_config": bool(target_version in supported) if supported else None,
    }


_EXECUTION_REQUEST_FIELDS = (
    "auto_apply",
    "apply_patch",
    "apply_package",
    "artifact_url",
    "migration",
    "migration_steps",
    "execute_migration",
    "rollback",
    "rollback_steps",
    "restart_node",
    # Explicit economics requests are recorded as ignored upgrade-execution
    # requests. Protocol upgrades must not activate live economics, fees,
    # rewards, or transfers through this record-only path.
    "activate_economics",
    "enable_economics",
    "economics_activation",
    "unlock_economics",
    "activate_live_economics",
    "enable_live_economics",
    "enable_fees",
    "enable_rewards",
    "enable_transfers",
)


def _record_only_boundary(payload: Json) -> Json:
    requested = []
    for key in _EXECUTION_REQUEST_FIELDS:
        if key in payload and payload.get(key) not in (None, "", False, [], {}):
            requested.append(key)
    return {
        "execution_model": "record_only_no_auto_apply",
        "governance_activation_record_only": True,
        "software_applied": False,
        "artifact_fetched": False,
        "artifact_apply_enabled": False,
        "migration_executed": False,
        "migration_execution_enabled": False,
        "rollback_available": False,
        "rollback_execution_enabled": False,
        "operator_action_required": True,
        "automatic_upgrade_supported": False,
        "restart_or_process_control_enabled": False,
        "requested_execution_fields_ignored": requested,
        "truth_boundary": (
            "Protocol upgrade txs record declaration/activation metadata only. "
            "They do not fetch, verify, apply, migrate, restart, or roll back node software."
        ),
    }


def _infer_upgrade_id(payload: Json, env: TxEnvelope) -> str:
    uid = _as_str(
        payload.get("upgrade_id") or payload.get("id") or payload.get("proposal_id")
    ).strip()
    if uid:
        return uid
    # Deterministic fallback.
    return f"upgrade:{env.signer}:{int(env.nonce)}"


def _apply_protocol_upgrade_declare(state: Json, env: TxEnvelope) -> Json:
    _require_system_env(env)
    parent_ref = _require_parent_ref(env)
    payload = _as_dict(env.payload)
    uid = _infer_upgrade_id(payload, env)

    version = _target_version(payload)
    if not version:
        raise ProtocolApplyError(
            "invalid_payload",
            "missing_upgrade_target_version",
            {"upgrade_id": uid, "required": "version or target_version or rule_target"},
        )
    target_support = _validate_target_supported(state, target_version=version, upgrade_id=uid)
    hsh = _as_str(payload.get("hash")).strip() or _as_str(payload.get("commit")).strip() or None

    proto = _ensure_protocol(state)
    upgrades = proto["upgrades"]
    assert isinstance(upgrades, dict)

    rec = upgrades.get(uid)
    if isinstance(rec, dict):
        existing_status = _as_str(rec.get("status")).strip().lower()
        if existing_status in {"scheduled", "effective", "activated"}:
            # Cannot re-declare an upgrade id after governance approval/scheduling.
            raise ProtocolApplyError("conflict", "upgrade_already_scheduled", {"upgrade_id": uid})
        existing_version = _as_str(rec.get("target_version") or rec.get("version")).strip()
        existing_hash = _as_str(rec.get("hash")).strip() or None
        if existing_version == version and existing_hash == hsh:
            # Exact replay/idempotency: do not rewrite the original declaration
            # height, nonce, payload, or target-support proof.
            return {
                "applied": "PROTOCOL_UPGRADE_DECLARE",
                "upgrade_id": uid,
                "version": existing_version,
                "target_version": existing_version,
                "hash": existing_hash,
                "deduped": True,
                "target_support": dict(_as_dict(rec.get("target_support"))),
                "record_only_boundary": dict(_as_dict(rec.get("record_only_boundary"))),
                "governance_parent_ref": _as_str(rec.get("governance_parent_ref")).strip() or parent_ref,
            }
        raise ProtocolApplyError(
            "conflict",
            "upgrade_already_declared",
            {
                "upgrade_id": uid,
                "declared_target_version": existing_version,
                "requested_target_version": version,
            },
        )

    upgrades[uid] = {
        "upgrade_id": uid,
        "version": version,
        "target_version": version,
        "hash": hsh,
        "status": "declared",
        "declared_at_height": int(_height_now(state, env)),
        "declared_at_nonce": int(env.nonce),
        "activation_height": None,
        "governance_approved_at_height": None,
        "governance_approved_at_nonce": None,
        "parent": parent_ref,
        "governance_parent_ref": parent_ref,
        "payload": payload,
        "target_support": target_support,
        "record_only_boundary": _record_only_boundary(payload),
    }

    return {
        "applied": "PROTOCOL_UPGRADE_DECLARE",
        "upgrade_id": uid,
        "version": version,
        "target_version": version,
        "hash": hsh,
        "target_support": target_support,
        "record_only_boundary": _record_only_boundary(payload),
        "governance_parent_ref": parent_ref,
    }


def _apply_protocol_upgrade_activate(state: Json, env: TxEnvelope) -> Json:
    _require_system_env(env)
    parent_ref = _require_parent_ref(env)
    payload = _as_dict(env.payload)
    uid = _infer_upgrade_id(payload, env)

    proto = _ensure_protocol(state)
    upgrades = proto["upgrades"]
    assert isinstance(upgrades, dict)

    rec = upgrades.get(uid)
    if not isinstance(rec, dict):
        raise ProtocolApplyError("not_found", "upgrade_not_declared", {"upgrade_id": uid})

    if rec.get("status") in {"scheduled", "effective", "activated"}:
        scheduled_record = _as_dict(_as_dict(proto.get("scheduled_upgrades")).get(uid))
        activation_record = dict(scheduled_record or rec)
        declared_version = _as_str(rec.get("target_version") or rec.get("version")).strip()
        requested_version = _target_version(payload)
        if requested_version and requested_version != declared_version:
            raise ProtocolApplyError(
                "conflict",
                "upgrade_duplicate_activation_conflict",
                {
                    "upgrade_id": uid,
                    "declared_target_version": declared_version,
                    "requested_target_version": requested_version,
                },
            )
        requested_activation_height = _as_int(payload.get("activation_height"), 0)
        existing_activation_height = _as_int(rec.get("activation_height") or activation_record.get("activation_height"), 0)
        if requested_activation_height > 0 and existing_activation_height > 0 and requested_activation_height != existing_activation_height:
            raise ProtocolApplyError(
                "conflict",
                "upgrade_duplicate_activation_conflict",
                {
                    "upgrade_id": uid,
                    "activation_height": int(existing_activation_height),
                    "requested_activation_height": int(requested_activation_height),
                },
            )
        boundary = _record_only_boundary(_as_dict(rec.get("activate_payload") or rec.get("payload")))
        return {
            "applied": "PROTOCOL_UPGRADE_ACTIVATE",
            "upgrade_id": uid,
            "deduped": True,
            "governance_activation_record": activation_record,
            "record_only_boundary": boundary,
            "governance_parent_ref": _as_str(rec.get("activation_parent_ref")).strip() or parent_ref,
        }

    declared_version = _as_str(rec.get("target_version") or rec.get("version")).strip()
    version = _target_version(payload) or declared_version
    if not version:
        raise ProtocolApplyError(
            "invalid_payload",
            "missing_upgrade_target_version",
            {"upgrade_id": uid, "required": "version or prior declared target_version"},
        )
    if declared_version and version != declared_version:
        raise ProtocolApplyError(
            "conflict",
            "upgrade_activation_target_mismatch",
            {"upgrade_id": uid, "declared_target_version": declared_version, "activation_target_version": version},
        )
    target_support = _validate_target_supported(state, target_version=version, upgrade_id=uid)
    activation_height = _validate_activation_height(state, payload, upgrade_id=uid, env=env)

    rec["status"] = "scheduled"
    rec["activation_height"] = int(activation_height)
    rec["governance_approved_at_height"] = int(_height_now(state, env))
    rec["governance_approved_at_nonce"] = int(env.nonce)
    rec["activate_payload"] = payload
    rec["activation_parent_ref"] = parent_ref
    rec["target_version"] = version
    rec["target_support"] = target_support
    rec["record_only_boundary"] = _record_only_boundary(payload)
    upgrades[uid] = rec

    hsh = _as_str(payload.get("hash")).strip() or _as_str(rec.get("hash")).strip() or None

    boundary = _record_only_boundary(payload)
    activation_record = {
        "upgrade_id": uid,
        "version": version,
        "target_version": version,
        "hash": hsh,
        "status": "scheduled",
        "activation_height": int(activation_height),
        "governance_approved_at_height": int(_height_now(state, env)),
        "governance_approved_at_nonce": int(env.nonce),
        "record_only_boundary": boundary,
        "activation_pending": True,
        "effective_now": False,
        "effective_at_height": int(activation_height),
        "governance_parent_ref": parent_ref,
        "software_applied": False,
        "artifact_fetched": False,
        "migration_executed": False,
        "rollback_available": False,
        "operator_action_required": True,
        "automatic_upgrade_supported": False,
        "economics_activation_allowed": False,
        "target_support": target_support,
        "truth_boundary": (
            "Governance approval schedules a public compatibility record at activation_height. "
            "It does not apply software, run migrations, restart nodes, roll back state, or activate economics."
        ),
    }
    proto["scheduled_upgrades"] = dict(_as_dict(proto.get("scheduled_upgrades")))
    proto["scheduled_upgrades"][uid] = dict(activation_record)
    # Compatibility read model retained for existing API/tests.  It is an
    # activation *record*, not proof that software has changed.
    proto["active"] = dict(activation_record)
    proto["governance_activation_record"] = dict(activation_record)

    return {
        "applied": "PROTOCOL_UPGRADE_ACTIVATE",
        "upgrade_id": uid,
        "version": version,
        "target_version": version,
        "hash": hsh,
        "deduped": False,
        "activation_height": int(activation_height),
        "governance_activation_record": dict(activation_record),
        "record_only_boundary": boundary,
        "governance_parent_ref": parent_ref,
    }



# ---------------------------------------------------------------------------
# Constitution upgrade record-only governance path
# ---------------------------------------------------------------------------

_PRIVATE_IDENTITY_EVIDENCE_FIELDS = frozenset(
    {
        "raw_identity_evidence",
        "raw_poh_evidence",
        "face_video",
        "video_evidence",
        "government_id",
        "government_identifier",
        "device_fingerprint",
        "liveness_secret",
        "recovery_secret",
        "private_key",
    }
)


def _ensure_constitution(state: Json) -> Json:
    c = _ensure_root_dict(state, "constitution")
    if not isinstance(c.get("upgrades"), dict):
        c["upgrades"] = {}
    if not isinstance(c.get("scheduled_upgrades"), dict):
        c["scheduled_upgrades"] = {}
    return c


def _constitution_id(payload: Json, env: TxEnvelope) -> str:
    cid = _as_str(payload.get("constitution_id") or payload.get("upgrade_id") or payload.get("id")).strip()
    if cid:
        return cid
    return f"constitution:{env.signer}:{int(env.nonce)}"


def _target_constitution_version(payload: Json) -> str:
    return _as_str(payload.get("constitution_version") or payload.get("version")).strip()


def _hash_value(payload: Json, *keys: str) -> str:
    for key in keys:
        value = _as_str(payload.get(key)).strip()
        if value:
            return value
    return ""


def _validate_constitution_hash(value: str, *, field: str, constitution_id: str) -> str:
    v = str(value or "").strip()
    raw = v[7:] if v.startswith("sha256:") else v
    if len(raw) != 64 or any(ch not in "0123456789abcdefABCDEF" for ch in raw):
        raise ProtocolApplyError(
            "invalid_payload",
            "constitution_hash_must_be_sha256",
            {"constitution_id": constitution_id, "field": field},
        )
    return "sha256:" + raw.lower()


def _validate_constitution_payload_public(payload: Json, *, constitution_id: str) -> None:
    present = sorted(k for k in payload.keys() if str(k) in _PRIVATE_IDENTITY_EVIDENCE_FIELDS)
    if present:
        raise ProtocolApplyError(
            "forbidden",
            "constitution_upgrade_contains_private_identity_evidence",
            {"constitution_id": constitution_id, "fields": present},
        )
    bypass = []
    for key in ("bypass_rights_floor", "disable_rights_floor", "weaken_rights_floor"):
        if key in payload and payload.get(key) not in (None, False, "", 0):
            bypass.append(key)
    if bypass:
        raise ProtocolApplyError(
            "forbidden",
            "constitution_upgrade_rights_floor_bypass_forbidden",
            {"constitution_id": constitution_id, "fields": bypass},
        )


def _constitution_record_only_boundary(payload: Json) -> Json:
    return {
        "execution_model": "record_only_no_auto_apply",
        "governance_activation_record_only": True,
        "document_fetched": False,
        "document_apply_enabled": False,
        "rights_floor_bypass_allowed": False,
        "private_identity_evidence_allowed": False,
        "operator_action_required": True,
        "automatic_constitution_apply_supported": False,
        "truth_boundary": (
            "Constitution upgrade txs record governance-approved version/hash metadata only. "
            "They do not fetch documents, expose raw identity evidence, or bypass the rights floor."
        ),
    }


def constitution_effective_view(state: Json, *, at_height: int | None = None) -> Json:
    # Read model only: callers may render old/new constitution metadata at an
    # arbitrary block height without mutating consensus state during inspection.
    c = _as_dict(state.get("constitution"))
    height = _as_int(at_height, _as_int(state.get("height"), 0))
    scheduled = _as_dict(c.get("scheduled_upgrades"))
    effective: list[Json] = []
    pending: list[Json] = []
    for _cid, rec_raw in sorted(scheduled.items(), key=lambda item: str(item[0])):
        rec = _as_dict(rec_raw)
        activation_height = _as_int(rec.get("activation_height"), 0)
        if activation_height > 0 and height >= activation_height:
            effective.append(rec)
        else:
            pending.append(rec)
    active = effective[-1] if effective else _as_dict(c.get("active"))
    return {
        "current_height": int(height),
        "active": dict(active),
        "effective_scheduled_count": len(effective),
        "pending_scheduled_count": len(pending),
        "pending": list(pending),
        "activation_model": "read_model_by_block_height_record_only",
    }


def _apply_constitution_upgrade_declare(state: Json, env: TxEnvelope) -> Json:
    _require_system_env(env)
    parent_ref = _require_parent_ref(env)
    payload = _as_dict(env.payload)
    cid = _constitution_id(payload, env)
    version = _target_constitution_version(payload)
    if not version:
        raise ProtocolApplyError("invalid_payload", "missing_constitution_version", {"constitution_id": cid})
    _validate_constitution_payload_public(payload, constitution_id=cid)
    document_hash = _validate_constitution_hash(_hash_value(payload, "document_hash", "hash"), field="document_hash", constitution_id=cid)
    traceability_hash = _validate_constitution_hash(_hash_value(payload, "traceability_hash"), field="traceability_hash", constitution_id=cid)

    constitution = _ensure_constitution(state)
    upgrades = constitution["upgrades"]
    assert isinstance(upgrades, dict)
    existing = upgrades.get(cid)
    if isinstance(existing, dict):
        if _as_str(existing.get("status")).strip().lower() in {"scheduled", "effective", "activated"}:
            raise ProtocolApplyError("conflict", "constitution_upgrade_already_scheduled", {"constitution_id": cid})
        if (
            _as_str(existing.get("version")).strip() == version
            and _as_str(existing.get("document_hash")).strip() == document_hash
            and _as_str(existing.get("traceability_hash")).strip() == traceability_hash
        ):
            return {
                "applied": "CONSTITUTION_UPGRADE_DECLARE",
                "constitution_id": cid,
                "version": version,
                "deduped": True,
                "record_only_boundary": dict(_as_dict(existing.get("record_only_boundary"))),
            }
        raise ProtocolApplyError("conflict", "constitution_upgrade_already_declared", {"constitution_id": cid})

    rec = {
        "constitution_id": cid,
        "version": version,
        "document_hash": document_hash,
        "traceability_hash": traceability_hash,
        "rights_floor_hash": _as_str(payload.get("rights_floor_hash")).strip() or None,
        "status": "declared",
        "declared_at_height": int(_height_now(state, env)),
        "declared_at_nonce": int(env.nonce),
        "activation_height": None,
        "governance_approved_at_height": None,
        "governance_parent_ref": parent_ref,
        "payload": payload,
        "record_only_boundary": _constitution_record_only_boundary(payload),
    }
    upgrades[cid] = rec
    return {"applied": "CONSTITUTION_UPGRADE_DECLARE", "constitution_id": cid, "version": version, "record_only_boundary": rec["record_only_boundary"]}


def _apply_constitution_upgrade_activate(state: Json, env: TxEnvelope) -> Json:
    _require_system_env(env)
    parent_ref = _require_parent_ref(env)
    payload = _as_dict(env.payload)
    cid = _constitution_id(payload, env)
    _validate_constitution_payload_public(payload, constitution_id=cid)
    constitution = _ensure_constitution(state)
    upgrades = constitution["upgrades"]
    assert isinstance(upgrades, dict)
    rec = upgrades.get(cid)
    if not isinstance(rec, dict):
        raise ProtocolApplyError("not_found", "constitution_upgrade_not_declared", {"constitution_id": cid})
    if _as_str(rec.get("status")).strip().lower() in {"scheduled", "effective", "activated"}:
        requested_activation_height = _as_int(payload.get("activation_height"), 0)
        existing_activation_height = _as_int(rec.get("activation_height"), 0)
        if requested_activation_height > 0 and existing_activation_height > 0 and requested_activation_height != existing_activation_height:
            raise ProtocolApplyError(
                "conflict",
                "constitution_duplicate_activation_conflict",
                {"constitution_id": cid, "activation_height": existing_activation_height, "requested_activation_height": requested_activation_height},
            )
        return {
            "applied": "CONSTITUTION_UPGRADE_ACTIVATE",
            "constitution_id": cid,
            "deduped": True,
            "governance_activation_record": dict(_as_dict(_as_dict(constitution.get("scheduled_upgrades")).get(cid)) or rec),
        }

    version = _target_constitution_version(payload) or _as_str(rec.get("version")).strip()
    if version != _as_str(rec.get("version")).strip():
        raise ProtocolApplyError("conflict", "constitution_activation_version_mismatch", {"constitution_id": cid})
    if payload.get("document_hash"):
        requested_doc_hash = _validate_constitution_hash(_as_str(payload.get("document_hash")), field="document_hash", constitution_id=cid)
        if requested_doc_hash != _as_str(rec.get("document_hash")).strip():
            raise ProtocolApplyError("conflict", "constitution_activation_document_hash_mismatch", {"constitution_id": cid})
    if payload.get("traceability_hash"):
        requested_trace_hash = _validate_constitution_hash(_as_str(payload.get("traceability_hash")), field="traceability_hash", constitution_id=cid)
        if requested_trace_hash != _as_str(rec.get("traceability_hash")).strip():
            raise ProtocolApplyError("conflict", "constitution_activation_traceability_hash_mismatch", {"constitution_id": cid})

    activation_height = _validate_activation_height(state, payload, upgrade_id=cid, env=env)
    boundary = _constitution_record_only_boundary(payload)
    activation_record = {
        "constitution_id": cid,
        "version": version,
        "document_hash": _as_str(rec.get("document_hash")).strip(),
        "traceability_hash": _as_str(rec.get("traceability_hash")).strip(),
        "rights_floor_hash": rec.get("rights_floor_hash"),
        "status": "scheduled",
        "activation_height": int(activation_height),
        "governance_approved_at_height": int(_height_now(state, env)),
        "governance_approved_at_nonce": int(env.nonce),
        "activation_pending": True,
        "effective_now": False,
        "effective_at_height": int(activation_height),
        "governance_parent_ref": parent_ref,
        "record_only_boundary": boundary,
        "truth_boundary": boundary["truth_boundary"],
    }
    rec.update(activation_record)
    rec["activate_payload"] = payload
    upgrades[cid] = rec
    constitution["scheduled_upgrades"] = dict(_as_dict(constitution.get("scheduled_upgrades")))
    constitution["scheduled_upgrades"][cid] = dict(activation_record)
    constitution["governance_activation_record"] = dict(activation_record)
    return {"applied": "CONSTITUTION_UPGRADE_ACTIVATE", "constitution_id": cid, "activation_height": int(activation_height), "governance_activation_record": dict(activation_record), "record_only_boundary": boundary}


PROTOCOL_TX_TYPES = {"PROTOCOL_UPGRADE_DECLARE", "PROTOCOL_UPGRADE_ACTIVATE", "CONSTITUTION_UPGRADE_DECLARE", "CONSTITUTION_UPGRADE_ACTIVATE"}


def apply_protocol(state: Json, env: TxEnvelope) -> Json | None:
    t = _as_str(env.tx_type).strip().upper()
    if t not in PROTOCOL_TX_TYPES:
        return None

    if t == "PROTOCOL_UPGRADE_DECLARE":
        return _apply_protocol_upgrade_declare(state, env)
    if t == "PROTOCOL_UPGRADE_ACTIVATE":
        return _apply_protocol_upgrade_activate(state, env)
    if t == "CONSTITUTION_UPGRADE_DECLARE":
        return _apply_constitution_upgrade_declare(state, env)
    if t == "CONSTITUTION_UPGRADE_ACTIVATE":
        return _apply_constitution_upgrade_activate(state, env)

    return None


__all__ = ["ProtocolApplyError", "apply_protocol", "constitution_effective_view"]
