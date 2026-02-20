from __future__ import annotations

"""weall.runtime.apply.protocol

Protocol-upgrade domain apply semantics.

Canon txs (v2.x):
  - PROTOCOL_UPGRADE_DECLARE  (SYSTEM, block, receipt_only, parent=GOV_EXECUTE)
  - PROTOCOL_UPGRADE_ACTIVATE (SYSTEM, block, receipt_only, parent=PROTOCOL_UPGRADE_DECLARE)

This module is intentionally minimal and deterministic:
  - It records declared upgrades (append/overwrite by upgrade_id)
  - It records activation (sets active version / active upgrade)
  - It does not perform migrations; it only records state for auditing/UI.

State surface:
state["protocol"] = {
  "upgrades": {
     upgrade_id: {
        "upgrade_id": str,
        "version": str|None,
        "hash": str|None,
        "status": "declared"|"activated",
        "declared_at_height": int,
        "declared_at_nonce": int,
        "activated_at_height": int|None,
        "activated_at_nonce": int|None,
        "parent": str|None,
        "payload": {...},
     },
  },
  "active": {
     "upgrade_id": str|None,
     "version": str|None,
     "hash": str|None,
     "activated_at_height": int,
     "activated_at_nonce": int,
  }
}

Notes:
- Parent constraints + receipt_only are enforced at admission/router level.
- We still enforce env.system=True for defense-in-depth.
"""

from dataclasses import dataclass
from typing import Any, Dict, Optional

from weall.runtime.tx_admission import TxEnvelope

Json = Dict[str, Any]


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


def _height_now(state: Json) -> int:
    return _as_int(state.get("height"), 0) + 1


def _infer_upgrade_id(payload: Json, env: TxEnvelope) -> str:
    uid = _as_str(payload.get("upgrade_id") or payload.get("id") or payload.get("proposal_id")).strip()
    if uid:
        return uid
    # Deterministic fallback.
    return f"upgrade:{env.signer}:{int(env.nonce)}"


def _apply_protocol_upgrade_declare(state: Json, env: TxEnvelope) -> Json:
    _require_system_env(env)
    payload = _as_dict(env.payload)
    uid = _infer_upgrade_id(payload, env)

    version = _as_str(payload.get("version")).strip() or _as_str(payload.get("target_version")).strip() or None
    hsh = _as_str(payload.get("hash")).strip() or _as_str(payload.get("commit")).strip() or None

    proto = _ensure_protocol(state)
    upgrades = proto["upgrades"]
    assert isinstance(upgrades, dict)

    # Idempotency: overwriting the same uid is allowed (canonical latest payload wins).
    rec = upgrades.get(uid)
    if isinstance(rec, dict) and rec.get("status") == "activated":
        # Cannot re-declare an already activated upgrade id.
        raise ProtocolApplyError("conflict", "upgrade_already_activated", {"upgrade_id": uid})

    upgrades[uid] = {
        "upgrade_id": uid,
        "version": version,
        "hash": hsh,
        "status": "declared",
        "declared_at_height": int(_height_now(state)),
        "declared_at_nonce": int(env.nonce),
        "activated_at_height": None,
        "activated_at_nonce": None,
        "parent": env.parent,
        "payload": payload,
    }

    return {"applied": "PROTOCOL_UPGRADE_DECLARE", "upgrade_id": uid, "version": version, "hash": hsh}


def _apply_protocol_upgrade_activate(state: Json, env: TxEnvelope) -> Json:
    _require_system_env(env)
    payload = _as_dict(env.payload)
    uid = _infer_upgrade_id(payload, env)

    proto = _ensure_protocol(state)
    upgrades = proto["upgrades"]
    assert isinstance(upgrades, dict)

    rec = upgrades.get(uid)
    if not isinstance(rec, dict):
        raise ProtocolApplyError("not_found", "upgrade_not_declared", {"upgrade_id": uid})

    if rec.get("status") == "activated":
        return {"applied": "PROTOCOL_UPGRADE_ACTIVATE", "upgrade_id": uid, "deduped": True}

    rec["status"] = "activated"
    rec["activated_at_height"] = int(_height_now(state))
    rec["activated_at_nonce"] = int(env.nonce)
    rec["activate_payload"] = payload
    upgrades[uid] = rec

    version = _as_str(payload.get("version")).strip() or _as_str(rec.get("version")).strip() or None
    hsh = _as_str(payload.get("hash")).strip() or _as_str(rec.get("hash")).strip() or None

    proto["active"] = {
        "upgrade_id": uid,
        "version": version,
        "hash": hsh,
        "activated_at_height": int(_height_now(state)),
        "activated_at_nonce": int(env.nonce),
    }

    return {"applied": "PROTOCOL_UPGRADE_ACTIVATE", "upgrade_id": uid, "version": version, "hash": hsh, "deduped": False}


PROTOCOL_TX_TYPES = {"PROTOCOL_UPGRADE_DECLARE", "PROTOCOL_UPGRADE_ACTIVATE"}


def apply_protocol(state: Json, env: TxEnvelope) -> Optional[Json]:
    t = _as_str(env.tx_type).strip().upper()
    if t not in PROTOCOL_TX_TYPES:
        return None

    if t == "PROTOCOL_UPGRADE_DECLARE":
        return _apply_protocol_upgrade_declare(state, env)
    if t == "PROTOCOL_UPGRADE_ACTIVATE":
        return _apply_protocol_upgrade_activate(state, env)

    return None


__all__ = ["ProtocolApplyError", "apply_protocol"]
