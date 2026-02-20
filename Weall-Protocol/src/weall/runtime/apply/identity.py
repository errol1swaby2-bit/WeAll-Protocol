from __future__ import annotations

"""weall.runtime.apply.identity

Identity / accounts / keys / devices / sessions / recovery apply semantics.

Public state surface expected by the runtime tests:

state["accounts"] = {
  account_id: {
    "account_id": str,
    "nonce": int,
    "locked": bool,
    "keys": {pubkey: {"pubkey": str, "active": bool}},
    "devices": {device_id: {"device_id": str, "active": bool, "pubkeys": [str], "label": str, "device_type": str}},
    "guardians": [account_id, ...],
    "security_policy": {...},
    "session_keys": {session_key: {...}},
    "recovery": {...},
  }
}

Global invariant added (production posture):
- Each account may have at most ONE active "node device" at a time.
- Node devices are registered through ACCOUNT_DEVICE_REGISTER with:
    payload.device_type/kind/type == "node"
  OR device_id begins with "node:"
  OR label begins with "node" (legacy convenience)

This makes the rule enforceable by consensus and applies across the network.
"""

from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Set

from weall.runtime.tx_admission import TxEnvelope

Json = Dict[str, Any]


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------

@dataclass
class IdentityApplyError(RuntimeError):
    code: str
    reason: str
    details: Json

    def __str__(self) -> str:
        return f"{self.code}:{self.reason}:{self.details}"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _as_dict(x: Any) -> Json:
    return x if isinstance(x, dict) else {}


def _as_str(x: Any) -> str:
    return x if isinstance(x, str) else ""


def _as_int(x: Any, default: int = 0) -> int:
    try:
        return int(x)
    except Exception:
        return default


def _ensure_root_dict(state: Json, key: str) -> Json:
    cur = state.get(key)
    if not isinstance(cur, dict):
        cur = {}
        state[key] = cur
    return cur


def _ensure_accounts(state: Json) -> Json:
    return _ensure_root_dict(state, "accounts")


def _ensure_identity_root(state: Json) -> Json:
    return _ensure_root_dict(state, "identity")


def _ensure_email_hash_to_account(state: Json) -> Json:
    root = _ensure_identity_root(state)
    cur = root.get("email_hash_to_account")
    if not isinstance(cur, dict):
        cur = {}
        root["email_hash_to_account"] = cur
    return cur


def _create_default_account(state: Json, account_id: str, *, nonce: int = 0) -> Json:
    accts = _ensure_accounts(state)
    cur = accts.get(account_id)
    if isinstance(cur, dict):
        return cur
    cur = {
        "account_id": account_id,
        "nonce": int(nonce),
        "locked": False,
        "keys": {},
        "devices": {},
        "guardians": [],
        "security_policy": {},
        "session_keys": {},
        "recovery": {},
    }
    accts[account_id] = cur
    return cur


def _ensure_keys(acct: Json) -> Json:
    cur = acct.get("keys")
    if not isinstance(cur, dict):
        cur = {}
        acct["keys"] = cur
    return cur


def _set_key_active(acct: Json, pubkey: str, active: bool) -> None:
    keys = _ensure_keys(acct)
    rec = keys.get(pubkey)
    if not isinstance(rec, dict):
        rec = {"pubkey": pubkey, "active": bool(active)}
    rec["active"] = bool(active)
    keys[pubkey] = rec
    acct["keys"] = keys


def _ensure_devices(acct: Json) -> Json:
    cur = acct.get("devices")
    if not isinstance(cur, dict):
        cur = {}
        acct["devices"] = cur
    return cur


def _ensure_guardians(acct: Json) -> List[str]:
    cur = acct.get("guardians")
    if not isinstance(cur, list):
        cur = []
        acct["guardians"] = cur
    return [g for g in cur if isinstance(g, str) and g.strip()]


def _ensure_security_policy(acct: Json) -> Json:
    cur = acct.get("security_policy")
    if not isinstance(cur, dict):
        cur = {}
        acct["security_policy"] = cur
    return cur


def _ensure_session_keys(acct: Json) -> Json:
    cur = acct.get("session_keys")
    if not isinstance(cur, dict):
        cur = {}
        acct["session_keys"] = cur
    return cur


def _ensure_recovery(acct: Json) -> Json:
    cur = acct.get("recovery")
    if not isinstance(cur, dict):
        cur = {}
        acct["recovery"] = cur
    return cur


def _ensure_recovery_requests(state: Json) -> Json:
    root = _ensure_root_dict(state, "recovery")
    cur = root.get("requests")
    if not isinstance(cur, dict):
        cur = {}
        root["requests"] = cur
    return cur


def _ensure_recovery_receipts(state: Json) -> Json:
    root = _ensure_root_dict(state, "recovery")
    cur = root.get("receipts")
    if not isinstance(cur, dict):
        cur = {}
        root["receipts"] = cur
    return cur


def _require_system_tx(env: TxEnvelope) -> None:
    if not bool(getattr(env, "system", False)):
        raise IdentityApplyError("forbidden", "system_only", {"tx_type": env.tx_type})


# ---------------------------------------------------------------------------
# ACCOUNT_REGISTER
# ---------------------------------------------------------------------------

def _apply_account_register(state: Json, env: TxEnvelope) -> Json:
    payload = _as_dict(env.payload)

    # Backward-compatible payload shape:
    #   - signer is the canonical account_id
    #   - payload.account_id (if provided) must match signer
    claimed = _as_str(payload.get("account_id") or payload.get("account")).strip()
    if claimed and claimed != str(env.signer):
        raise IdentityApplyError("invalid_payload", "account_id_mismatch", {"signer": env.signer, "account_id": claimed})

    acct = _create_default_account(state, env.signer, nonce=env.nonce)

    # optional seed pubkey
    pubkey = _as_str(payload.get("pubkey")).strip()
    if pubkey:
        _set_key_active(acct, pubkey, True)

    # optional email uniqueness fingerprint
    email_hash = _as_str(payload.get("email_hash") or payload.get("contact_hash")).strip()
    if email_hash:
        # validate: hex sha256 (64 chars)
        eh = email_hash.lower()
        if len(eh) != 64 or any(c not in "0123456789abcdef" for c in eh):
            raise IdentityApplyError("invalid_payload", "invalid_email_hash", {"email_hash": email_hash})

        idx = _ensure_email_hash_to_account(state)
        existing = idx.get(eh)
        if existing and str(existing) != str(env.signer):
            raise IdentityApplyError(
                "forbidden",
                "email_already_registered",
                {"email_hash": eh, "existing_account": existing, "account": env.signer},
            )
        idx[eh] = str(env.signer)
        acct["email_hash"] = eh

    acct["nonce"] = int(env.nonce)
    return {"applied": "ACCOUNT_REGISTER", "account": env.signer}


# ---------------------------------------------------------------------------
# ACCOUNT_KEY_ADD / ACCOUNT_KEY_REVOKE
# ---------------------------------------------------------------------------

def _apply_account_key_add(state: Json, env: TxEnvelope) -> Json:
    acct = _create_default_account(state, env.signer, nonce=env.nonce)
    payload = _as_dict(env.payload)
    pubkey = _as_str(payload.get("pubkey")).strip()
    if not pubkey:
        raise IdentityApplyError("invalid_payload", "missing_pubkey", {"tx_type": env.tx_type})
    _set_key_active(acct, pubkey, True)
    acct["nonce"] = int(env.nonce)
    return {"applied": "ACCOUNT_KEY_ADD", "account": env.signer, "pubkey": pubkey}


def _apply_account_key_revoke(state: Json, env: TxEnvelope) -> Json:
    acct = _create_default_account(state, env.signer, nonce=env.nonce)
    payload = _as_dict(env.payload)
    pubkey = _as_str(payload.get("pubkey")).strip()
    if not pubkey:
        raise IdentityApplyError("invalid_payload", "missing_pubkey", {"tx_type": env.tx_type})
    _set_key_active(acct, pubkey, False)
    acct["nonce"] = int(env.nonce)
    return {"applied": "ACCOUNT_KEY_REVOKE", "account": env.signer, "pubkey": pubkey}


# ---------------------------------------------------------------------------
# ACCOUNT_DEVICE_REGISTER / ACCOUNT_DEVICE_REVOKE
# ---------------------------------------------------------------------------

def _apply_account_device_register(state: Json, env: TxEnvelope) -> Json:
    acct = _create_default_account(state, env.signer, nonce=env.nonce)
    payload = _as_dict(env.payload)
    device_id = _as_str(payload.get("device_id")).strip()
    if not device_id:
        raise IdentityApplyError("invalid_payload", "missing_device_id", {"tx_type": env.tx_type})

    devices = _ensure_devices(acct)

    # ------------------------------------------------------------
    # One-node-per-account (on-chain invariant, production posture)
    #
    # We treat a "node device" as either:
    #   - payload.device_type/kind/type == "node"
    #   - OR device_id begins with "node:"
    #   - OR payload.label begins with "node" (legacy convenience)
    #
    # If a different active node device already exists for the account,
    # reject the registration (fail-closed).
    # ------------------------------------------------------------
    device_type = _as_str(payload.get("device_type") or payload.get("kind") or payload.get("type")).strip().lower()
    label = _as_str(payload.get("label")).strip()
    is_node = (
        device_type == "node"
        or device_id.startswith("node:")
        or (label.lower().startswith("node") if label else False)
    )

    if is_node:
        for did, drec in list(devices.items()):
            if did == device_id:
                continue
            if not isinstance(drec, dict):
                continue
            if not bool(drec.get("active", False)):
                continue

            d_type = _as_str(drec.get("device_type") or drec.get("kind") or drec.get("type")).strip().lower()
            d_label = _as_str(drec.get("label")).strip()
            d_is_node = (
                d_type == "node"
                or str(did).startswith("node:")
                or (d_label.lower().startswith("node") if d_label else False)
            )
            if d_is_node:
                raise IdentityApplyError(
                    "forbidden",
                    "one_node_per_account",
                    {
                        "tx_type": env.tx_type,
                        "account": env.signer,
                        "existing_device_id": did,
                        "new_device_id": device_id,
                    },
                )

    rec = devices.get(device_id)
    deduped = isinstance(rec, dict) and bool(rec.get("active", False))

    if not isinstance(rec, dict):
        rec = {"device_id": device_id, "active": True, "pubkeys": [], "label": "", "device_type": ""}

    rec["active"] = True

    if label:
        rec["label"] = label

    if is_node:
        rec["device_type"] = "node"
    elif device_type:
        rec["device_type"] = device_type

    pubkey = _as_str(payload.get("pubkey")).strip()
    if pubkey:
        pubkeys = rec.get("pubkeys")
        if not isinstance(pubkeys, list):
            pubkeys = []
        if pubkey not in pubkeys:
            pubkeys.append(pubkey)
        rec["pubkeys"] = pubkeys

    devices[device_id] = rec
    acct["nonce"] = int(env.nonce)
    return {
        "applied": "ACCOUNT_DEVICE_REGISTER",
        "account": env.signer,
        "device_id": device_id,
        "device_type": rec.get("device_type"),
        "deduped": bool(deduped),
    }


def _apply_account_device_revoke(state: Json, env: TxEnvelope) -> Json:
    acct = _create_default_account(state, env.signer, nonce=env.nonce)
    payload = _as_dict(env.payload)
    device_id = _as_str(payload.get("device_id")).strip()
    if not device_id:
        raise IdentityApplyError("invalid_payload", "missing_device_id", {"tx_type": env.tx_type})

    devices = _ensure_devices(acct)
    rec = devices.get(device_id)
    if not isinstance(rec, dict):
        return {"applied": "ACCOUNT_DEVICE_REVOKE", "account": env.signer, "device_id": device_id, "deduped": True}

    if not bool(rec.get("active", False)):
        return {"applied": "ACCOUNT_DEVICE_REVOKE", "account": env.signer, "device_id": device_id, "deduped": True}

    rec["active"] = False
    devices[device_id] = rec
    acct["nonce"] = int(env.nonce)
    return {"applied": "ACCOUNT_DEVICE_REVOKE", "account": env.signer, "device_id": device_id, "deduped": False}


# ---------------------------------------------------------------------------
# ACCOUNT_GUARDIAN_ADD / ACCOUNT_GUARDIAN_REMOVE
# ---------------------------------------------------------------------------

def _apply_account_guardian_add(state: Json, env: TxEnvelope) -> Json:
    acct = _create_default_account(state, env.signer, nonce=env.nonce)
    payload = _as_dict(env.payload)
    guardian = _as_str(payload.get("guardian")).strip()
    if not guardian:
        raise IdentityApplyError("invalid_payload", "missing_guardian", {"tx_type": env.tx_type})

    guardians = _ensure_guardians(acct)
    if guardian in guardians:
        return {"applied": "ACCOUNT_GUARDIAN_ADD", "deduped": True, "account": env.signer, "guardian": guardian}

    guardians.append(guardian)
    acct["guardians"] = guardians
    acct["nonce"] = int(env.nonce)
    return {"applied": "ACCOUNT_GUARDIAN_ADD", "deduped": False, "account": env.signer, "guardian": guardian}


def _apply_account_guardian_remove(state: Json, env: TxEnvelope) -> Json:
    acct = _create_default_account(state, env.signer, nonce=env.nonce)
    payload = _as_dict(env.payload)
    guardian = _as_str(payload.get("guardian")).strip()
    if not guardian:
        raise IdentityApplyError("invalid_payload", "missing_guardian", {"tx_type": env.tx_type})

    guardians = _ensure_guardians(acct)
    if guardian not in guardians:
        return {"applied": "ACCOUNT_GUARDIAN_REMOVE", "deduped": True, "account": env.signer, "guardian": guardian}

    acct["guardians"] = [g for g in guardians if g != guardian]
    acct["nonce"] = int(env.nonce)
    return {"applied": "ACCOUNT_GUARDIAN_REMOVE", "deduped": False, "account": env.signer, "guardian": guardian}


# ---------------------------------------------------------------------------
# ACCOUNT_SECURITY_POLICY_SET
# ---------------------------------------------------------------------------

def _apply_account_security_policy_set(state: Json, env: TxEnvelope) -> Json:
    acct = _create_default_account(state, env.signer, nonce=env.nonce)
    payload = _as_dict(env.payload)

    pol = _ensure_security_policy(acct)
    # Simple allowlist: accept any dict-ish fields under policy.
    for k, v in payload.items():
        pol[str(k)] = v

    acct["security_policy"] = pol
    acct["nonce"] = int(env.nonce)
    return {"applied": "ACCOUNT_SECURITY_POLICY_SET", "account": env.signer}


# ---------------------------------------------------------------------------
# ACCOUNT_SESSION_KEY_ISSUE / ACCOUNT_SESSION_KEY_REVOKE
# ---------------------------------------------------------------------------

def _apply_account_session_key_issue(state: Json, env: TxEnvelope) -> Json:
    acct = _create_default_account(state, env.signer, nonce=env.nonce)
    payload = _as_dict(env.payload)

    sk = _as_str(payload.get("session_key")).strip()
    if not sk:
        raise IdentityApplyError("invalid_payload", "missing_session_key", {"tx_type": env.tx_type})

    sess = _ensure_session_keys(acct)
    if sk in sess:
        return {"applied": "ACCOUNT_SESSION_KEY_ISSUE", "deduped": True, "account": env.signer, "session_key": sk}

    sess[sk] = {
        "session_key": sk,
        "issued_at_nonce": int(env.nonce),
        "active": True,
        "meta": _as_dict(payload.get("meta")),
    }
    acct["session_keys"] = sess
    acct["nonce"] = int(env.nonce)
    return {"applied": "ACCOUNT_SESSION_KEY_ISSUE", "deduped": False, "account": env.signer, "session_key": sk}


def _apply_account_session_key_revoke(state: Json, env: TxEnvelope) -> Json:
    acct = _create_default_account(state, env.signer, nonce=env.nonce)
    payload = _as_dict(env.payload)

    sk = _as_str(payload.get("session_key")).strip()
    if not sk:
        raise IdentityApplyError("invalid_payload", "missing_session_key", {"tx_type": env.tx_type})

    sess = _ensure_session_keys(acct)
    rec = sess.get(sk)
    if not isinstance(rec, dict):
        return {"applied": "ACCOUNT_SESSION_KEY_REVOKE", "deduped": True, "account": env.signer, "session_key": sk}

    if not bool(rec.get("active", False)):
        return {"applied": "ACCOUNT_SESSION_KEY_REVOKE", "deduped": True, "account": env.signer, "session_key": sk}

    rec["active"] = False
    rec["revoked_at_nonce"] = int(env.nonce)
    sess[sk] = rec
    acct["session_keys"] = sess
    acct["nonce"] = int(env.nonce)
    return {"applied": "ACCOUNT_SESSION_KEY_REVOKE", "deduped": False, "account": env.signer, "session_key": sk}


# ---------------------------------------------------------------------------
# ACCOUNT_RECOVERY_CONFIG_SET
# ---------------------------------------------------------------------------

def _apply_account_recovery_config_set(state: Json, env: TxEnvelope) -> Json:
    acct = _create_default_account(state, env.signer, nonce=env.nonce)
    payload = _as_dict(env.payload)
    rec = _ensure_recovery(acct)

    if "enabled" in payload:
        rec["enabled"] = bool(payload.get("enabled"))
    if "threshold" in payload:
        rec["threshold"] = _as_int(payload.get("threshold"), 0)

    acct["recovery"] = rec
    acct["nonce"] = int(env.nonce)
    return {"applied": "ACCOUNT_RECOVERY_CONFIG_SET", "account": env.signer}


# ---------------------------------------------------------------------------
# ACCOUNT_RECOVERY_REQUEST / CANCEL / APPROVE / FINALIZE / RECEIPT
# ---------------------------------------------------------------------------

def _apply_account_recovery_request(state: Json, env: TxEnvelope) -> Json:
    payload = _as_dict(env.payload)
    target = _as_str(payload.get("target")).strip()
    if not target:
        raise IdentityApplyError("invalid_payload", "missing_target", {"tx_type": env.tx_type})

    rid = _as_str(payload.get("request_id")).strip()
    if not rid:
        rid = f"recovery:{target}:{env.signer}:{int(env.nonce)}"

    reqs = _ensure_recovery_requests(state)
    if rid in reqs:
        return {"applied": "ACCOUNT_RECOVERY_REQUEST", "deduped": True, "request_id": rid, "target": target}

    reqs[rid] = {
        "request_id": rid,
        "target": target,
        "requester": env.signer,
        "status": "open",
        "approvals": [],
        "created_at_nonce": int(env.nonce),
        "payload": payload,
    }
    return {"applied": "ACCOUNT_RECOVERY_REQUEST", "deduped": False, "request_id": rid, "target": target}


def _apply_account_recovery_cancel(state: Json, env: TxEnvelope) -> Json:
    payload = _as_dict(env.payload)
    rid = _as_str(payload.get("request_id")).strip()
    if not rid:
        raise IdentityApplyError("invalid_payload", "missing_request_id", {"tx_type": env.tx_type})

    reqs = _ensure_recovery_requests(state)
    req = reqs.get(rid)
    if not isinstance(req, dict):
        raise IdentityApplyError("not_found", "recovery_request_not_found", {"request_id": rid})

    if req.get("requester") != env.signer:
        raise IdentityApplyError("forbidden", "only_requester_can_cancel", {"request_id": rid})

    if req.get("status") != "open":
        return {"applied": "ACCOUNT_RECOVERY_CANCEL", "deduped": True, "request_id": rid}

    req["status"] = "cancelled"
    req["cancelled_at_nonce"] = int(env.nonce)
    req["cancel_payload"] = payload
    reqs[rid] = req
    return {"applied": "ACCOUNT_RECOVERY_CANCEL", "deduped": False, "request_id": rid}


def _apply_account_recovery_approve(state: Json, env: TxEnvelope) -> Json:
    payload = _as_dict(env.payload)
    rid = _as_str(payload.get("request_id")).strip()
    if not rid:
        raise IdentityApplyError("invalid_payload", "missing_request_id", {"tx_type": env.tx_type})

    reqs = _ensure_recovery_requests(state)
    req = reqs.get(rid)
    if not isinstance(req, dict):
        raise IdentityApplyError("not_found", "recovery_request_not_found", {"request_id": rid})

    if req.get("status") != "open":
        return {"applied": "ACCOUNT_RECOVERY_APPROVE", "deduped": True, "request_id": rid}

    approvals = req.get("approvals")
    if not isinstance(approvals, list):
        approvals = []
    if env.signer not in approvals:
        approvals.append(env.signer)
    req["approvals"] = approvals
    req["last_approved_at_nonce"] = int(env.nonce)
    reqs[rid] = req
    return {"applied": "ACCOUNT_RECOVERY_APPROVE", "deduped": False, "request_id": rid, "approvals": approvals}


def _apply_account_recovery_finalize(state: Json, env: TxEnvelope) -> Json:
    payload = _as_dict(env.payload)
    rid = _as_str(payload.get("request_id")).strip()
    if not rid:
        raise IdentityApplyError("invalid_payload", "missing_request_id", {"tx_type": env.tx_type})

    reqs = _ensure_recovery_requests(state)
    req = reqs.get(rid)
    if not isinstance(req, dict):
        raise IdentityApplyError("not_found", "recovery_request_not_found", {"request_id": rid})

    if req.get("status") != "open":
        return {"applied": "ACCOUNT_RECOVERY_FINALIZE", "deduped": True, "request_id": rid}

    target = _as_str(req.get("target")).strip()
    if not target:
        raise IdentityApplyError("invalid_state", "missing_target_in_request", {"request_id": rid})

    acct = _create_default_account(state, target)

    # Finalize is a SYSTEM receipt in production and typically only carries
    # request_id (the requested new_pubkey lives on the original request).
    # For backward-compat / tool usage, accept new_pubkey either in finalize
    # payload *or* from the stored request payload.
    new_pubkey = _as_str(payload.get("new_pubkey")).strip()
    if not new_pubkey:
        req_payload = req.get("payload")
        if isinstance(req_payload, dict):
            new_pubkey = _as_str(req_payload.get("new_pubkey")).strip()
    if not new_pubkey:
        raise IdentityApplyError(
            "invalid_state",
            "missing_new_pubkey",
            {"tx_type": env.tx_type, "request_id": rid},
        )

    _set_key_active(acct, new_pubkey, True)
    req["status"] = "finalized"
    reqs[rid] = req
    return {"applied": "ACCOUNT_RECOVERY_FINALIZE", "request_id": rid, "target": target}


def _apply_account_recovery_receipt(state: Json, env: TxEnvelope) -> Json:
    _require_system_tx(env)
    payload = _as_dict(env.payload)
    rid = _as_str(payload.get("request_id")).strip()
    if not rid:
        raise IdentityApplyError("invalid_payload", "missing_request_id", {"tx_type": env.tx_type})

    receipts = _ensure_recovery_receipts(state)
    if rid in receipts:
        return {"applied": "ACCOUNT_RECOVERY_RECEIPT", "deduped": True, "request_id": rid}
    receipts[rid] = {
        "request_id": rid,
        "ok": bool(payload.get("ok", True)),
        "code": _as_str(payload.get("code")).strip() or "ok",
        "details": _as_dict(payload.get("details")),
    }
    return {"applied": "ACCOUNT_RECOVERY_RECEIPT", "request_id": rid}


# ---------------------------------------------------------------------------
# ACCOUNT_LOCK / ACCOUNT_UNLOCK (system)
# ---------------------------------------------------------------------------

def _apply_account_lock(state: Json, env: TxEnvelope) -> Json:
    _require_system_tx(env)
    payload = _as_dict(env.payload)
    target = _as_str(payload.get("target")).strip()
    if not target:
        raise IdentityApplyError("invalid_payload", "missing_target", {"tx_type": env.tx_type})
    acct = _create_default_account(state, target)
    acct["locked"] = True
    return {"applied": "ACCOUNT_LOCK", "account": target}


def _apply_account_unlock(state: Json, env: TxEnvelope) -> Json:
    _require_system_tx(env)
    payload = _as_dict(env.payload)
    target = _as_str(payload.get("target")).strip()
    if not target:
        raise IdentityApplyError("invalid_payload", "missing_target", {"tx_type": env.tx_type})
    acct = _create_default_account(state, target)
    acct["locked"] = False
    return {"applied": "ACCOUNT_UNLOCK", "account": target}


# ---------------------------------------------------------------------------
# Router
# ---------------------------------------------------------------------------

IDENTITY_TX_TYPES: Set[str] = {
    "ACCOUNT_REGISTER",
    "ACCOUNT_KEY_ADD",
    "ACCOUNT_KEY_REVOKE",
    "ACCOUNT_DEVICE_REGISTER",
    "ACCOUNT_DEVICE_REVOKE",
    "ACCOUNT_GUARDIAN_ADD",
    "ACCOUNT_GUARDIAN_REMOVE",
    "ACCOUNT_SECURITY_POLICY_SET",
    "ACCOUNT_SESSION_KEY_ISSUE",
    "ACCOUNT_SESSION_KEY_REVOKE",
    "ACCOUNT_RECOVERY_CONFIG_SET",
    "ACCOUNT_RECOVERY_REQUEST",
    "ACCOUNT_RECOVERY_CANCEL",
    "ACCOUNT_RECOVERY_APPROVE",
    "ACCOUNT_RECOVERY_FINALIZE",
    "ACCOUNT_RECOVERY_RECEIPT",
    "ACCOUNT_LOCK",
    "ACCOUNT_UNLOCK",
}


def apply_identity(state: Json, env: TxEnvelope) -> Optional[Json]:
    """Apply identity txs. Returns meta dict if handled; otherwise None."""
    t = str(env.tx_type or "").strip()
    if t not in IDENTITY_TX_TYPES:
        return None

    if t == "ACCOUNT_REGISTER":
        return _apply_account_register(state, env)
    if t == "ACCOUNT_KEY_ADD":
        return _apply_account_key_add(state, env)
    if t == "ACCOUNT_KEY_REVOKE":
        return _apply_account_key_revoke(state, env)
    if t == "ACCOUNT_DEVICE_REGISTER":
        return _apply_account_device_register(state, env)
    if t == "ACCOUNT_DEVICE_REVOKE":
        return _apply_account_device_revoke(state, env)
    if t == "ACCOUNT_GUARDIAN_ADD":
        return _apply_account_guardian_add(state, env)
    if t == "ACCOUNT_GUARDIAN_REMOVE":
        return _apply_account_guardian_remove(state, env)
    if t == "ACCOUNT_SECURITY_POLICY_SET":
        return _apply_account_security_policy_set(state, env)
    if t == "ACCOUNT_SESSION_KEY_ISSUE":
        return _apply_account_session_key_issue(state, env)
    if t == "ACCOUNT_SESSION_KEY_REVOKE":
        return _apply_account_session_key_revoke(state, env)
    if t == "ACCOUNT_RECOVERY_CONFIG_SET":
        return _apply_account_recovery_config_set(state, env)
    if t == "ACCOUNT_RECOVERY_REQUEST":
        return _apply_account_recovery_request(state, env)
    if t == "ACCOUNT_RECOVERY_CANCEL":
        return _apply_account_recovery_cancel(state, env)
    if t == "ACCOUNT_RECOVERY_APPROVE":
        return _apply_account_recovery_approve(state, env)
    if t == "ACCOUNT_RECOVERY_FINALIZE":
        return _apply_account_recovery_finalize(state, env)
    if t == "ACCOUNT_RECOVERY_RECEIPT":
        return _apply_account_recovery_receipt(state, env)
    if t == "ACCOUNT_LOCK":
        return _apply_account_lock(state, env)
    if t == "ACCOUNT_UNLOCK":
        return _apply_account_unlock(state, env)

    return None
