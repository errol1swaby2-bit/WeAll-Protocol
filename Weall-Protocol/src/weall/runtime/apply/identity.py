from __future__ import annotations

import hashlib
from typing import Any

from ..errors import ApplyError
from ..tx_admission_types import TxEnvelope

Json = dict[str, Any]


def _as_int(x: Any, default: int = 0) -> int:
    try:
        return int(x)
    except Exception:
        return default


def _as_str(x: Any) -> str:
    if x is None:
        return ""
    return str(x)


def _payload(env: TxEnvelope) -> Json:
    p = getattr(env, "payload", None)
    if not isinstance(p, dict):
        return {}
    return p


def _ensure(state: Json, k: str, default: Any) -> Any:
    if k not in state or state.get(k) is None:
        state[k] = default
    return state[k]


def _expect_nonce(a: Json, env: TxEnvelope) -> int:
    want = _as_int(a.get("nonce"), 0) + 1
    got = _as_int(getattr(env, "nonce", None), 0)

    # Policy B (protocol-aligned): nonce is monotonic and can advance even if
    # prior attempts rejected. Apply-time therefore tolerates gaps.
    #
    # System receipts are often emitted with nonce=0; in that case we consume
    # the next expected nonce deterministically.
    if bool(getattr(env, "system", False)) and got == 0:
        got = want

    if got < want:
        raise ApplyError("invalid_tx", "bad_nonce", {"want": want, "got": got})
    return got


def _require_not_banned_or_locked(state: Json, account_id: str) -> Json:
    accounts = _ensure(state, "accounts", {})
    if not isinstance(accounts, dict):
        raise ApplyError("invalid_state", "accounts_not_dict", {})
    a = accounts.get(account_id)
    if not isinstance(a, dict):
        raise ApplyError("invalid_tx", "unknown_account", {"account_id": account_id})
    if a.get("banned") is True:
        raise ApplyError("forbidden", "account_banned", {"account_id": account_id})
    if a.get("locked") is True:
        raise ApplyError("forbidden", "account_locked", {"account_id": account_id})
    return a


def _mk_key_id(pubkey: str) -> str:
    # Stable, deterministic key id for by_id mapping
    h = hashlib.sha256(pubkey.encode("utf-8")).hexdigest()
    return f"k:{h[:16]}"


def _mk_device_id_hash(device_id: str) -> str:
    h = hashlib.sha256(device_id.encode("utf-8")).hexdigest()
    return f"d:{h[:16]}"


def _apply_account_register(state: Json, env: TxEnvelope) -> Json:
    accounts = _ensure(state, "accounts", {})
    if not isinstance(accounts, dict):
        raise ApplyError("invalid_state", "accounts_not_dict", {})

    signer = _as_str(env.signer)
    if not signer:
        raise ApplyError("invalid_tx", "missing_signer", {})

    if signer in accounts:
        raise ApplyError("invalid_tx", "account_exists", {"account_id": signer})

    p = _payload(env)
    pubkey = _as_str(p.get("pubkey") or "").strip()
    if not pubkey:
        raise ApplyError("invalid_tx", "missing_pubkey", {})

    # NOTE: PoH tier bootstraps to 1 on register (email-verified identity layer is enforced elsewhere).
    accounts[signer] = {
        "nonce": _as_int(getattr(env, "nonce", 0), 0),
        "poh_tier": 1,
        "banned": False,
        "locked": False,
        "reputation": 0,
        "keys": {
            "by_id": {
                _mk_key_id(pubkey): {
                    "pubkey": pubkey,
                    "key_type": "main",
                    "revoked": False,
                    "revoked_at": None,
                }
            }
        },
        "devices": {"by_id": {}},
        "recovery": {"config": None, "proposals": {}},
        # Added: session keys for private endpoint gating (e.g., media upload).
        # API security expects accounts[acct]["session_keys"][session_key] dicts.
        "session_keys": {},
    }
    return state


def _apply_account_key_add(state: Json, env: TxEnvelope) -> Json:
    a = _require_not_banned_or_locked(state, env.signer)
    _expect_nonce(a, env)
    p = _payload(env)

    pubkey = _as_str(p.get("pubkey") or "").strip()
    key_type = _as_str(p.get("key_type") or "secondary").strip().lower()
    if not pubkey:
        raise ApplyError("invalid_tx", "missing_pubkey", {})

    keys = a.get("keys")
    if not isinstance(keys, dict):
        keys = {}
        a["keys"] = keys
    by_id = keys.get("by_id")
    if not isinstance(by_id, dict):
        by_id = {}
        keys["by_id"] = by_id

    kid = _mk_key_id(pubkey)
    if kid in by_id and isinstance(by_id.get(kid), dict) and by_id[kid].get("revoked") is not True:
        raise ApplyError("invalid_tx", "key_exists", {"pubkey": pubkey})

    by_id[kid] = {
        "pubkey": pubkey,
        "key_type": key_type,
        "revoked": False,
        "revoked_at": None,
    }
    a["nonce"] = _as_int(a.get("nonce"), 0) + 1
    return state


def _apply_account_key_revoke(state: Json, env: TxEnvelope) -> Json:
    a = _require_not_banned_or_locked(state, env.signer)
    _expect_nonce(a, env)
    p = _payload(env)

    pubkey = _as_str(p.get("pubkey") or "").strip()
    if not pubkey:
        raise ApplyError("invalid_tx", "missing_pubkey", {})

    keys = a.get("keys")
    if not isinstance(keys, dict) or not isinstance(keys.get("by_id"), dict):
        raise ApplyError("invalid_state", "keys_not_configured", {})

    by_id = keys["by_id"]
    match_kid: str | None = None
    for kid, rec in by_id.items():
        if not isinstance(rec, dict):
            continue
        if _as_str(rec.get("pubkey") or "").strip() == pubkey and rec.get("revoked") is not True:
            match_kid = kid
            break

    if not match_kid:
        raise ApplyError("invalid_tx", "unknown_key", {"pubkey": pubkey})

    by_id[match_kid]["revoked"] = True
    by_id[match_kid]["revoked_at"] = _as_int(state.get("height"), 0)
    a["nonce"] = _as_int(a.get("nonce"), 0) + 1
    return state


def _apply_account_device_register(state: Json, env: TxEnvelope) -> Json:
    a = _require_not_banned_or_locked(state, env.signer)
    exp = _expect_nonce(a, env)
    p = _payload(env)

    device_id = _as_str(p.get("device_id") or "").strip()
    device_type = _as_str(p.get("device_type") or "").strip().lower()
    label = _as_str(p.get("label") or "").strip()
    pubkey = _as_str(p.get("pubkey") or "").strip()

    if not device_id:
        raise ApplyError("invalid_tx", "missing_device_id", {})
    if not device_type:
        # Back-compat: tests and older clients may omit device_type.
        # Infer "node" from conventional identifiers; otherwise default.
        if device_id.startswith("node:") or label.lower().startswith("node"):
            device_type = "node"
        else:
            device_type = "generic"
    if not pubkey:
        raise ApplyError("invalid_tx", "missing_pubkey", {"device_id": device_id})

    devices = a.get("devices")
    if not isinstance(devices, dict):
        devices = {}
        a["devices"] = devices
    by_id = devices.get("by_id")
    if not isinstance(by_id, dict):
        by_id = {}
        devices["by_id"] = by_id

    if (
        device_id in by_id
        and isinstance(by_id.get(device_id), dict)
        and by_id[device_id].get("revoked") is not True
    ):
        raise ApplyError("invalid_tx", "device_exists", {"device_id": device_id})

    # Enforce one node device per account (used to gate peer hello identity).
    if device_type == "node":
        for _did, _rec in by_id.items():
            if _did == device_id:
                continue
            if not isinstance(_rec, dict):
                continue
            if _rec.get("revoked") is True:
                continue
            if _as_str(_rec.get("device_type") or "").strip().lower() == "node":
                # IMPORTANT: tests assert this reason string is visible.
                raise ApplyError(
                    "forbidden", "one_node_per_account", {"device_id": device_id, "existing": _did}
                )

    by_id[device_id] = {
        "device_id": device_id,
        "device_type": device_type,
        "label": label or None,
        "pubkey": pubkey,
        "revoked": False,
        "revoked_at": None,
        "device_id_hash": _mk_device_id_hash(device_id),
    }

    a["nonce"] = exp
    return state


def _apply_account_device_revoke(state: Json, env: TxEnvelope) -> Json:
    a = _require_not_banned_or_locked(state, env.signer)
    exp = _expect_nonce(a, env)
    p = _payload(env)

    device_id = _as_str(p.get("device_id") or "").strip()
    if not device_id:
        raise ApplyError("invalid_tx", "missing_device_id", {})

    devices = a.get("devices")
    if not isinstance(devices, dict) or not isinstance(devices.get("by_id"), dict):
        raise ApplyError("invalid_tx", "no_devices", {})

    by_id = devices["by_id"]
    rec = by_id.get(device_id)
    if not isinstance(rec, dict) or rec.get("revoked") is True:
        raise ApplyError("invalid_tx", "unknown_device", {"device_id": device_id})

    rec["revoked"] = True
    rec["revoked_at"] = _as_int(state.get("height"), 0)

    a["nonce"] = exp
    return state


# --------------------------------------------------------------------
# Added: session key issue/revoke (required by API private endpoint gates)
# --------------------------------------------------------------------
def _apply_account_session_key_issue(state: Json, env: TxEnvelope) -> Json:
    """Issue or refresh an on-chain session key.

    Accepted payload shapes:
      - {"session_key": "...", "ttl_s": 3600}
      - {"session_pubkey": "...", "expires_ts_ms": 1700000000000}
      - legacy alias: {"session": "..."}
    """
    a = _require_not_banned_or_locked(state, env.signer)
    exp = _expect_nonce(a, env)
    p = _payload(env)

    sk = _as_str(p.get("session_key") or p.get("session_pubkey") or p.get("session") or "").strip()
    if not sk:
        raise ApplyError("invalid_tx", "missing_session_key", {})

    ttl_s = _as_int(p.get("ttl_s"), 0)
    if ttl_s <= 0:
        # Derive TTL from expires_ts_ms if provided and chain time exists.
        try:
            ex_ms = int(p.get("expires_ts_ms") or 0)
        except Exception:
            ex_ms = 0
        now_s = _as_int(state.get("time"), 0)
        now_ms = now_s * 1000
        if ex_ms > 0 and now_ms > 0:
            ttl_s = max(0, int((ex_ms - now_ms) // 1000))

    ttl_s = max(0, int(ttl_s))

    sessions = a.get("session_keys")
    if not isinstance(sessions, dict):
        sessions = {}
        a["session_keys"] = sessions

    issued_at_ts = _as_int(state.get("time"), 0)
    if issued_at_ts < 0:
        issued_at_ts = 0

    sessions[sk] = {
        "active": True,
        "issued_at_ts": issued_at_ts,
        "ttl_s": ttl_s,
        "issued_at_height": _as_int(state.get("height"), 0),
    }

    a["nonce"] = exp
    return state


def _apply_account_session_key_revoke(state: Json, env: TxEnvelope) -> Json:
    a = _require_not_banned_or_locked(state, env.signer)
    exp = _expect_nonce(a, env)
    p = _payload(env)

    sk = _as_str(p.get("session_key") or p.get("session_pubkey") or p.get("session") or "").strip()
    if not sk:
        raise ApplyError("invalid_tx", "missing_session_key", {})

    sessions = a.get("session_keys")
    if not isinstance(sessions, dict):
        raise ApplyError("invalid_tx", "no_session_keys", {})

    rec = sessions.get(sk)
    if not isinstance(rec, dict):
        raise ApplyError("invalid_tx", "unknown_session_key", {"session_key": sk})

    rec["active"] = False
    rec["revoked_at_height"] = _as_int(state.get("height"), 0)
    rec["revoked_at_ts"] = _as_int(state.get("time"), 0)

    a["nonce"] = exp
    return state


def _apply_account_lock(state: Json, env: TxEnvelope) -> Json:
    # System tx: lock a target account.
    p = _payload(env)
    target = _as_str(p.get("target") or "").strip()
    if not target:
        raise ApplyError("invalid_tx", "missing_target", {})

    accounts = _ensure(state, "accounts", {})
    if not isinstance(accounts, dict):
        raise ApplyError("invalid_state", "accounts_not_dict", {})

    a = accounts.get(target)
    if not isinstance(a, dict):
        # Autocreate for MVP? Keep consistent with existing tests.
        accounts[target] = {
            "nonce": 0,
            "poh_tier": 0,
            "banned": False,
            "locked": False,
            "reputation": 0,
        }
        a = accounts[target]

    exp = _expect_nonce(a, env)

    a["locked"] = True
    a["nonce"] = exp
    return state


def _apply_account_unlock(state: Json, env: TxEnvelope) -> Json:
    p = _payload(env)
    target = _as_str(p.get("target") or "").strip()
    if not target:
        raise ApplyError("invalid_tx", "missing_target", {})

    accounts = _ensure(state, "accounts", {})
    if not isinstance(accounts, dict):
        raise ApplyError("invalid_state", "accounts_not_dict", {})

    a = accounts.get(target)
    if not isinstance(a, dict):
        raise ApplyError("invalid_tx", "unknown_account", {"account_id": target})

    exp = _expect_nonce(a, env)
    a["locked"] = False
    a["nonce"] = exp
    return state


def _apply_account_ban(state: Json, env: TxEnvelope) -> Json:
    p = _payload(env)
    target = _as_str(p.get("target") or "").strip()
    if not target:
        raise ApplyError("invalid_tx", "missing_target", {})

    accounts = _ensure(state, "accounts", {})
    if not isinstance(accounts, dict):
        raise ApplyError("invalid_state", "accounts_not_dict", {})

    a = accounts.get(target)
    if not isinstance(a, dict):
        raise ApplyError("invalid_tx", "unknown_account", {"account_id": target})

    exp = _expect_nonce(a, env)
    a["banned"] = True
    a["nonce"] = exp
    return state


def _apply_account_unban(state: Json, env: TxEnvelope) -> Json:
    p = _payload(env)
    target = _as_str(p.get("target") or "").strip()
    if not target:
        raise ApplyError("invalid_tx", "missing_target", {})

    accounts = _ensure(state, "accounts", {})
    if not isinstance(accounts, dict):
        raise ApplyError("invalid_state", "accounts_not_dict", {})

    a = accounts.get(target)
    if not isinstance(a, dict):
        raise ApplyError("invalid_tx", "unknown_account", {"account_id": target})

    exp = _expect_nonce(a, env)
    a["banned"] = False
    a["nonce"] = exp
    return state




def _normalized_guardians(a: Json) -> tuple[Json, list[str], int]:
    recovery = a.get("recovery")
    if not isinstance(recovery, dict):
        recovery = {}
        a["recovery"] = recovery

    cfg = recovery.get("config")
    if not isinstance(cfg, dict):
        cfg = {}
        recovery["config"] = cfg

    raw_guardians = cfg.get("guardians")
    guardians: list[str] = []
    if isinstance(raw_guardians, list):
        for g in raw_guardians:
            gs = _as_str(g).strip()
            if gs and gs not in guardians:
                guardians.append(gs)

    threshold = _as_int(cfg.get("threshold"), 0)
    if guardians and threshold <= 0:
        threshold = min(1, len(guardians))
    if guardians and threshold > len(guardians):
        threshold = len(guardians)

    cfg["guardians"] = guardians
    cfg["threshold"] = threshold
    return recovery, guardians, threshold


def _iter_recovery_requests(state: Json):
    accounts = _ensure(state, "accounts", {})
    if not isinstance(accounts, dict):
        raise ApplyError("invalid_state", "accounts_not_dict", {})
    for account_id, acct in accounts.items():
        if not isinstance(acct, dict):
            continue
        recovery = acct.get("recovery")
        if not isinstance(recovery, dict):
            continue
        requests = recovery.get("requests")
        if not isinstance(requests, dict):
            continue
        yield account_id, acct, recovery, requests


def _find_recovery_request(state: Json, request_id: str) -> tuple[str, Json, Json, Json]:
    for account_id, acct, recovery, requests in _iter_recovery_requests(state):
        req = requests.get(request_id)
        if isinstance(req, dict):
            return account_id, acct, recovery, req
    raise ApplyError("invalid_tx", "unknown_request", {"request_id": request_id})


def _apply_account_security_policy_set(state: Json, env: TxEnvelope) -> Json:
    a = _require_not_banned_or_locked(state, env.signer)
    exp = _expect_nonce(a, env)
    p = _payload(env)

    raw_policy = p.get("policy")
    if isinstance(raw_policy, dict):
        policy = dict(raw_policy)
    else:
        policy = {}

    for key in ("lock_on_recovery_request", "require_guardian_threshold_for_unlock"):
        if key in p and p.get(key) is not None:
            policy[key] = bool(p.get(key))
    if p.get("session_ttl_s") is not None:
        policy["session_ttl_s"] = _as_int(p.get("session_ttl_s"), 0)

    a["security_policy"] = policy
    a["nonce"] = exp
    return state


def _apply_account_guardian_add(state: Json, env: TxEnvelope) -> Json:
    a = _require_not_banned_or_locked(state, env.signer)
    exp = _expect_nonce(a, env)
    p = _payload(env)

    guardian_id = _as_str(p.get("guardian_id") or "").strip()
    if not guardian_id:
        raise ApplyError("invalid_tx", "missing_guardian_id", {})
    if guardian_id == _as_str(env.signer).strip():
        raise ApplyError("invalid_tx", "guardian_self_reference", {})

    recovery, guardians, threshold = _normalized_guardians(a)
    if guardian_id in guardians:
        raise ApplyError("invalid_tx", "guardian_exists", {"guardian_id": guardian_id})
    guardians.append(guardian_id)
    recovery["config"] = {"guardians": guardians, "threshold": max(1, threshold)}

    a["nonce"] = exp
    return state


def _apply_account_guardian_remove(state: Json, env: TxEnvelope) -> Json:
    a = _require_not_banned_or_locked(state, env.signer)
    exp = _expect_nonce(a, env)
    p = _payload(env)

    guardian_id = _as_str(p.get("guardian_id") or "").strip()
    if not guardian_id:
        raise ApplyError("invalid_tx", "missing_guardian_id", {})

    recovery, guardians, threshold = _normalized_guardians(a)
    if guardian_id not in guardians:
        raise ApplyError("invalid_tx", "unknown_guardian", {"guardian_id": guardian_id})
    guardians = [g for g in guardians if g != guardian_id]
    if guardians:
        threshold = min(max(1, threshold), len(guardians))
        recovery["config"] = {"guardians": guardians, "threshold": threshold}
    else:
        recovery["config"] = None

    a["nonce"] = exp
    return state

def _apply_account_recovery_config_set(state: Json, env: TxEnvelope) -> Json:
    a = _require_not_banned_or_locked(state, env.signer)
    exp = _expect_nonce(a, env)
    p = _payload(env)

    cfg = p.get("config")
    if not isinstance(cfg, dict):
        # Back-compat: allow the flat payload shape used in MVP tests.
        cfg = {
            "guardians": p.get("guardians"),
            "threshold": p.get("threshold"),
        }

    guardians = cfg.get("guardians")
    threshold = cfg.get("threshold")

    if not isinstance(guardians, list) or not guardians:
        raise ApplyError("invalid_tx", "invalid_guardians", {})
    guardians_norm: list[str] = []
    for g in guardians:
        gs = _as_str(g).strip()
        if not gs:
            continue
        guardians_norm.append(gs)
    if not guardians_norm:
        raise ApplyError("invalid_tx", "invalid_guardians", {})

    thr = _as_int(threshold, 0)
    if thr <= 0 or thr > len(guardians_norm):
        raise ApplyError("invalid_tx", "invalid_threshold", {"threshold": threshold})

    recovery = a.get("recovery")
    if not isinstance(recovery, dict):
        recovery = {}
        a["recovery"] = recovery
    recovery["config"] = {"guardians": guardians_norm, "threshold": thr}

    a["nonce"] = exp
    return state


def _apply_account_recovery_propose(state: Json, env: TxEnvelope) -> Json:
    a = _require_not_banned_or_locked(state, env.signer)
    exp = _expect_nonce(a, env)
    p = _payload(env)

    proposal_id = _as_str(p.get("proposal_id") or "").strip()
    new_pubkey = _as_str(p.get("new_pubkey") or "").strip()
    if not proposal_id:
        raise ApplyError("invalid_tx", "missing_proposal_id", {})
    if not new_pubkey:
        raise ApplyError("invalid_tx", "missing_new_pubkey", {})

    recovery = a.get("recovery")
    if not isinstance(recovery, dict) or not isinstance(recovery.get("config"), dict):
        raise ApplyError("invalid_tx", "recovery_not_configured", {})

    proposals = recovery.get("proposals")
    if not isinstance(proposals, dict):
        proposals = {}
        recovery["proposals"] = proposals

    if proposal_id in proposals:
        raise ApplyError("invalid_tx", "proposal_exists", {"proposal_id": proposal_id})

    proposals[proposal_id] = {
        "new_pubkey": new_pubkey,
        "approvals": [],
        "executed": False,
    }

    a["nonce"] = exp
    return state


def _apply_account_recovery_approve(state: Json, env: TxEnvelope) -> Json:
    p = _payload(env)
    request_id = _as_str(p.get("request_id") or "").strip()
    if not request_id:
        # Back-compat legacy proposal flow.
        return _apply_account_recovery_vote(state, env)

    account_id, _acct, _recovery, req = _find_recovery_request(state, request_id)
    accounts = _ensure(state, "accounts", {})
    if not isinstance(accounts, dict):
        raise ApplyError("invalid_state", "accounts_not_dict", {})
    subject = accounts.get(account_id)
    if not isinstance(subject, dict):
        raise ApplyError("invalid_tx", "unknown_account", {"account_id": account_id})
    if subject.get("banned") is True:
        raise ApplyError("forbidden", "account_banned", {"account_id": account_id})
    _recovery, guardians, threshold = _normalized_guardians(subject)

    guardian = _require_not_banned_or_locked(state, env.signer)
    exp = _expect_nonce(guardian, env)
    guardian_id = _as_str(env.signer).strip()
    if guardian_id not in guardians:
        raise ApplyError("forbidden", "not_a_guardian", {"guardian": guardian_id})

    status = _as_str(req.get("status") or "open").strip().lower()
    if status not in {"open", "approved"}:
        raise ApplyError("invalid_tx", "request_not_open", {"request_id": request_id, "status": status})

    approvals = req.get("approvals")
    if not isinstance(approvals, list):
        approvals = []
        req["approvals"] = approvals
    if guardian_id in approvals:
        raise ApplyError("invalid_tx", "already_approved", {"guardian": guardian_id, "request_id": request_id})

    approvals.append(guardian_id)
    req["guardian_threshold"] = threshold
    req["guardians_snapshot"] = list(guardians)
    req["status"] = "approved" if len(approvals) >= max(1, threshold) else "open"

    guardian["nonce"] = exp
    return state


def _apply_account_recovery_execute(state: Json, env: TxEnvelope) -> Json:
    # Execute if approvals >= threshold; adds new key.
    a = _require_not_banned_or_locked(state, env.signer)
    exp = _expect_nonce(a, env)
    p = _payload(env)

    proposal_id = _as_str(p.get("proposal_id") or "").strip()
    if not proposal_id:
        raise ApplyError("invalid_tx", "missing_proposal_id", {})

    recovery = a.get("recovery")
    if not isinstance(recovery, dict) or not isinstance(recovery.get("config"), dict):
        raise ApplyError("invalid_tx", "recovery_not_configured", {})

    cfg = recovery["config"]
    thr = _as_int(cfg.get("threshold"), 0)

    proposals = recovery.get("proposals")
    if not isinstance(proposals, dict):
        raise ApplyError("invalid_tx", "proposal_missing", {"proposal_id": proposal_id})

    prop = proposals.get(proposal_id)
    if not isinstance(prop, dict):
        raise ApplyError("invalid_tx", "proposal_missing", {"proposal_id": proposal_id})

    if prop.get("executed") is True:
        raise ApplyError("invalid_tx", "proposal_executed", {"proposal_id": proposal_id})

    approvals = prop.get("approvals")
    if not isinstance(approvals, list):
        approvals = []
    if len(approvals) < thr:
        raise ApplyError("forbidden", "threshold_not_met", {"have": len(approvals), "need": thr})

    new_pubkey = _as_str(prop.get("new_pubkey") or "").strip()
    if not new_pubkey:
        raise ApplyError("invalid_state", "missing_new_pubkey", {"proposal_id": proposal_id})

    # Add the new key
    keys = a.get("keys")
    if not isinstance(keys, dict):
        keys = {}
        a["keys"] = keys
    by_id = keys.get("by_id")
    if not isinstance(by_id, dict):
        by_id = {}
        keys["by_id"] = by_id

    kid = _mk_key_id(new_pubkey)
    if kid in by_id and isinstance(by_id.get(kid), dict) and by_id[kid].get("revoked") is not True:
        raise ApplyError("invalid_tx", "key_exists", {"pubkey": new_pubkey})

    by_id[kid] = {
        "pubkey": new_pubkey,
        "key_type": "recovered",
        "revoked": False,
        "revoked_at": None,
    }
    prop["executed"] = True

    a["nonce"] = exp
    return state


def _apply_account_recovery_request(state: Json, env: TxEnvelope) -> Json:
    """Open an account recovery request under the target account."""
    requester = _require_not_banned_or_locked(state, env.signer)
    exp = _expect_nonce(requester, env)
    p = _payload(env)

    request_id = _as_str(p.get("request_id") or "").strip()
    target = _as_str(p.get("target") or env.signer).strip()
    if not request_id:
        raise ApplyError("invalid_tx", "missing_request_id", {})
    if not target:
        raise ApplyError("invalid_tx", "missing_target", {})

    subject = _require_not_banned_or_locked(state, target)
    recovery, guardians, threshold = _normalized_guardians(subject)

    requests = recovery.get("requests")
    if not isinstance(requests, dict):
        requests = {}
        recovery["requests"] = requests

    if request_id in requests:
        raise ApplyError("invalid_tx", "request_exists", {"request_id": request_id})

    security_policy = subject.get("security_policy")
    lock_on_request = False
    if isinstance(security_policy, dict):
        lock_on_request = bool(security_policy.get("lock_on_recovery_request"))

    requests[request_id] = {
        "status": "open",
        "target": target,
        "requester": _as_str(env.signer).strip(),
        "approvals": [],
        "votes": {},
        "guardian_threshold": threshold,
        "guardians_snapshot": list(guardians),
        "created_at": _as_int(state.get("height"), 0),
    }

    if lock_on_request:
        subject["locked"] = True

    requester["nonce"] = exp
    return state




def _apply_account_recovery_cancel(state: Json, env: TxEnvelope) -> Json:
    actor = _require_not_banned_or_locked(state, env.signer)
    exp = _expect_nonce(actor, env)
    p = _payload(env)

    request_id = _as_str(p.get("request_id") or "").strip()
    if not request_id:
        raise ApplyError("invalid_tx", "missing_request_id", {})

    account_id, _acct, _recovery, req = _find_recovery_request(state, request_id)
    requester = _as_str(req.get("requester") or "").strip()
    if _as_str(env.signer).strip() not in {requester, account_id}:
        raise ApplyError("forbidden", "not_request_owner", {"request_id": request_id})

    status = _as_str(req.get("status") or "open").strip().lower()
    if status in {"cancelled", "finalized", "receipt_recorded"}:
        raise ApplyError("invalid_tx", "request_not_cancellable", {"request_id": request_id, "status": status})

    req["status"] = "cancelled"
    req["cancelled_by"] = _as_str(env.signer).strip()
    req["cancelled_at"] = _as_int(state.get("height"), 0)

    actor["nonce"] = exp
    return state


def _apply_account_recovery_finalize(state: Json, env: TxEnvelope) -> Json:
    p = _payload(env)
    request_id = _as_str(p.get("request_id") or "").strip()
    if not request_id:
        raise ApplyError("invalid_tx", "missing_request_id", {})

    account_id, acct, _recovery, req = _find_recovery_request(state, request_id)
    approvals = req.get("approvals")
    if not isinstance(approvals, list):
        approvals = []
    threshold = _as_int(req.get("guardian_threshold"), 0)
    if threshold <= 0:
        _, _, threshold = _normalized_guardians(acct)
    if len(approvals) < max(1, threshold):
        raise ApplyError("forbidden", "threshold_not_met", {"have": len(approvals), "need": max(1, threshold)})

    status = _as_str(req.get("status") or "").strip().lower()
    if status in {"cancelled", "finalized", "receipt_recorded"}:
        raise ApplyError("invalid_tx", "request_not_finalizable", {"request_id": request_id, "status": status})

    req["status"] = "finalized"
    req["finalized_at"] = _as_int(state.get("height"), 0)
    req["finalized_by"] = _as_str(getattr(env, "signer", "")).strip() or "SYSTEM"
    acct["locked"] = False
    return state


def _apply_account_recovery_receipt(state: Json, env: TxEnvelope) -> Json:
    p = _payload(env)
    request_id = _as_str(p.get("request_id") or "").strip()
    if not request_id:
        raise ApplyError("invalid_tx", "missing_request_id", {})

    _account_id, _acct, _recovery, req = _find_recovery_request(state, request_id)
    status = _as_str(p.get("status") or req.get("status") or "finalized").strip().lower()
    req["status"] = "receipt_recorded"
    req["receipt_status"] = status or "finalized"
    req["receipt_at"] = _as_int(state.get("height"), 0)
    return state

def _apply_account_recovery_vote(state: Json, env: TxEnvelope) -> Json:
    """Cast a vote on a recovery request (minimal MVP)."""
    a = _require_not_banned_or_locked(state, env.signer)
    exp = _expect_nonce(a, env)
    p = _payload(env)

    request_id = _as_str(p.get("request_id") or "").strip()
    vote = _as_str(p.get("vote") or "").strip().lower()
    if not request_id:
        raise ApplyError("invalid_tx", "missing_request_id", {})
    if vote not in {"yes", "no"}:
        raise ApplyError("invalid_tx", "invalid_vote", {"vote": vote})

    # For MVP smoke, requests live under the *subject* account (the one being recovered).
    # We search all accounts to find the request.
    accounts = _ensure(state, "accounts", {})
    if not isinstance(accounts, dict):
        raise ApplyError("invalid_state", "accounts_not_dict", {})

    found_req: Json | None = None
    for _aid, acct in accounts.items():
        if not isinstance(acct, dict):
            continue
        rec = acct.get("recovery")
        if not isinstance(rec, dict):
            continue
        reqs = rec.get("requests")
        if not isinstance(reqs, dict):
            continue
        r = reqs.get(request_id)
        if isinstance(r, dict):
            found_req = r
            break

    if found_req is None:
        raise ApplyError("invalid_tx", "unknown_request", {"request_id": request_id})

    votes = found_req.get("votes")
    if not isinstance(votes, dict):
        votes = {}
        found_req["votes"] = votes
    votes[env.signer] = vote

    a["nonce"] = exp
    return state


def apply_identity(state: Json, env: TxEnvelope) -> Json | None:
    tx = _as_str(getattr(env, "tx_type", "")).strip().upper()

    if tx == "ACCOUNT_REGISTER":
        return _apply_account_register(state, env)

    if tx == "ACCOUNT_KEY_ADD":
        return _apply_account_key_add(state, env)

    if tx == "ACCOUNT_KEY_REVOKE":
        return _apply_account_key_revoke(state, env)

    if tx == "ACCOUNT_DEVICE_REGISTER":
        return _apply_account_device_register(state, env)

    if tx == "ACCOUNT_DEVICE_REVOKE":
        return _apply_account_device_revoke(state, env)

    if tx == "ACCOUNT_SESSION_KEY_ISSUE":
        return _apply_account_session_key_issue(state, env)

    if tx == "ACCOUNT_SESSION_KEY_REVOKE":
        return _apply_account_session_key_revoke(state, env)

    if tx == "ACCOUNT_GUARDIAN_ADD":
        return _apply_account_guardian_add(state, env)

    if tx == "ACCOUNT_GUARDIAN_REMOVE":
        return _apply_account_guardian_remove(state, env)

    if tx == "ACCOUNT_SECURITY_POLICY_SET":
        return _apply_account_security_policy_set(state, env)

    if tx == "ACCOUNT_LOCK":
        return _apply_account_lock(state, env)

    if tx == "ACCOUNT_UNLOCK":
        return _apply_account_unlock(state, env)

    if tx == "ACCOUNT_BAN":
        return _apply_account_ban(state, env)

    if tx == "ACCOUNT_UNBAN":
        return _apply_account_unban(state, env)

    if tx == "ACCOUNT_RECOVERY_CONFIG_SET":
        return _apply_account_recovery_config_set(state, env)

    if tx == "ACCOUNT_RECOVERY_PROPOSE":
        return _apply_account_recovery_propose(state, env)

    if tx == "ACCOUNT_RECOVERY_APPROVE":
        return _apply_account_recovery_approve(state, env)

    if tx == "ACCOUNT_RECOVERY_EXECUTE":
        return _apply_account_recovery_execute(state, env)

    if tx == "ACCOUNT_RECOVERY_REQUEST":
        return _apply_account_recovery_request(state, env)

    if tx == "ACCOUNT_RECOVERY_CANCEL":
        return _apply_account_recovery_cancel(state, env)

    if tx == "ACCOUNT_RECOVERY_FINALIZE":
        return _apply_account_recovery_finalize(state, env)

    if tx == "ACCOUNT_RECOVERY_RECEIPT":
        return _apply_account_recovery_receipt(state, env)

    if tx == "ACCOUNT_RECOVERY_VOTE":
        return _apply_account_recovery_vote(state, env)

    # Not an identity-domain tx; allow other domain appliers to claim it.
    return None
