from __future__ import annotations

"""weall.runtime.apply.networking

Networking / peer discovery / peer moderation apply semantics.

Public state surface expected by the runtime tests:

state["peers"] = {
  "ads": {account_id: {...}},
  "tickets": {ticket_id: {"ticket_id": str, "owner_id": str, "status": "active|revoked", ...}},
  "connect_requests": [ {...}, ... ],
  "bans": {peer_id: {...}},
  "reputation_signals": [ {...}, ... ],
}

Notes:
- This is NOT a live networking stack; it records intent/state deterministically.
- System-only txs are enforced via env.system.
"""

from dataclasses import dataclass
from typing import Any, Dict, List, Optional

from weall.runtime.tx_admission import TxEnvelope

Json = Dict[str, Any]


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------

@dataclass
class NetworkingApplyError(RuntimeError):
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


def _pick(d: Json, *keys: str) -> Any:
    for k in keys:
        if k in d and d.get(k) is not None:
            return d.get(k)
    return None


def _mk_id(prefix: str, env: TxEnvelope, raw: Any) -> str:
    s = _as_str(raw).strip()
    if s:
        return s
    return f"{prefix}:{env.signer}:{int(env.nonce)}"


def _require_system_env(env: TxEnvelope) -> None:
    if not bool(getattr(env, "system", False)):
        raise NetworkingApplyError("forbidden", "system_only", {"tx_type": env.tx_type})


def _ensure_root_dict(state: Json, key: str) -> Json:
    cur = state.get(key)
    if not isinstance(cur, dict):
        cur = {}
        state[key] = cur
    return cur


def _ensure_peers(state: Json) -> Json:
    p = _ensure_root_dict(state, "peers")
    if not isinstance(p.get("ads"), dict):
        p["ads"] = {}
    if not isinstance(p.get("tickets"), dict):
        p["tickets"] = {}
    if not isinstance(p.get("connect_requests"), list):
        p["connect_requests"] = []
    if not isinstance(p.get("bans"), dict):
        p["bans"] = {}
    if not isinstance(p.get("reputation_signals"), list):
        p["reputation_signals"] = []
    return p


# ---------------------------------------------------------------------------
# PEER_ADVERTISE
# ---------------------------------------------------------------------------

def _apply_peer_advertise(state: Json, env: TxEnvelope) -> Json:
    peers = _ensure_peers(state)
    payload = _as_dict(env.payload)

    endpoint = _pick(payload, "endpoint", "url")
    if not endpoint:
        raise NetworkingApplyError("invalid_payload", "missing_endpoint", {"tx_type": env.tx_type})

    # In this simplified surface, peer_id == account_id unless explicitly provided.
    peer_id = _pick(payload, "peer_id", "peer", "id") or env.signer

    ads = peers["ads"]
    rec = ads.get(env.signer)
    deduped = isinstance(rec, dict) and rec.get("endpoint") == endpoint and rec.get("peer_id") == peer_id

    rec = {
        "account_id": env.signer,
        "peer_id": peer_id,
        "endpoint": endpoint,
        "nonce": int(env.nonce),
        "payload": payload,
    }
    ads[env.signer] = rec
    return {"applied": "PEER_ADVERTISE", "account_id": env.signer, "peer_id": peer_id, "deduped": deduped}


# ---------------------------------------------------------------------------
# PEER_RENDEZVOUS_TICKET_CREATE / REVOKE
# ---------------------------------------------------------------------------

def _apply_peer_rendezvous_ticket_create(state: Json, env: TxEnvelope) -> Json:
    peers = _ensure_peers(state)
    payload = _as_dict(env.payload)

    ticket_id = _mk_id("ticket", env, _pick(payload, "ticket_id", "id"))
    tickets = peers["tickets"]

    if ticket_id in tickets:
        return {"applied": "PEER_RENDEZVOUS_TICKET_CREATE", "ticket_id": ticket_id, "deduped": True}

    tickets[ticket_id] = {
        "ticket_id": ticket_id,
        "owner_id": env.signer,
        "status": "active",
        "revoked": False,
        "created_at_nonce": int(env.nonce),
        "payload": payload,
    }
    return {"applied": "PEER_RENDEZVOUS_TICKET_CREATE", "ticket_id": ticket_id, "deduped": False}


def _apply_peer_rendezvous_ticket_revoke(state: Json, env: TxEnvelope) -> Json:
    peers = _ensure_peers(state)
    payload = _as_dict(env.payload)

    ticket_id = _pick(payload, "ticket_id", "id")
    if not ticket_id:
        raise NetworkingApplyError("invalid_payload", "missing_ticket_id", {"tx_type": env.tx_type})

    tickets = peers["tickets"]
    rec = tickets.get(ticket_id)
    if not isinstance(rec, dict):
        raise NetworkingApplyError("not_found", "ticket_not_found", {"ticket_id": ticket_id})

    if rec.get("owner_id") != env.signer:
        raise NetworkingApplyError("forbidden", "only_owner_can_revoke", {"ticket_id": ticket_id})

    already = rec.get("status") == "revoked"
    rec["status"] = "revoked"
    rec["revoked"] = True
    rec["revoked_at_nonce"] = int(env.nonce)
    rec["revoke_payload"] = payload
    tickets[ticket_id] = rec
    return {"applied": "PEER_RENDEZVOUS_TICKET_REVOKE", "ticket_id": ticket_id, "deduped": already}


# ---------------------------------------------------------------------------
# PEER_REQUEST_CONNECT
# ---------------------------------------------------------------------------

def _apply_peer_request_connect(state: Json, env: TxEnvelope) -> Json:
    peers = _ensure_peers(state)
    payload = _as_dict(env.payload)

    to_peer_id = _pick(payload, "peer_id", "to_peer_id", "target_peer_id")
    endpoint = _pick(payload, "endpoint", "url")
    # allow either peer_id or endpoint
    if not to_peer_id and not endpoint:
        raise NetworkingApplyError("invalid_payload", "missing_target", {"tx_type": env.tx_type})

    peers["connect_requests"].append(
        {
            "from": env.signer,
            "to_peer_id": to_peer_id or None,
            "endpoint": endpoint or None,
            "nonce": int(env.nonce),
            "payload": payload,
        }
    )
    return {"applied": "PEER_REQUEST_CONNECT", "from": env.signer, "deduped": False}


# ---------------------------------------------------------------------------
# PEER_BAN_SET (system)
# ---------------------------------------------------------------------------

def _apply_peer_ban_set(state: Json, env: TxEnvelope) -> Json:
    _require_system_env(env)
    peers = _ensure_peers(state)
    payload = _as_dict(env.payload)

    peer_id = _pick(payload, "peer_id", "peer", "id")
    if not peer_id:
        raise NetworkingApplyError("invalid_payload", "missing_peer_id", {"tx_type": env.tx_type})

    banned = bool(payload.get("banned"))
    reason = _pick(payload, "reason") or ""

    rec = {
        "peer_id": peer_id,
        "banned": banned,
        "reason": reason,
        "nonce": int(env.nonce),
        "payload": payload,
    }
    peers["bans"][peer_id] = rec
    return {"applied": "PEER_BAN_SET", "peer_id": peer_id, "deduped": False}


# ---------------------------------------------------------------------------
# PEER_REPUTATION_SIGNAL (system)
# ---------------------------------------------------------------------------

def _apply_peer_reputation_signal(state: Json, env: TxEnvelope) -> Json:
    _require_system_env(env)
    peers = _ensure_peers(state)
    payload = _as_dict(env.payload)

    peer_id = _pick(payload, "peer_id", "peer", "id")
    if not peer_id:
        raise NetworkingApplyError("invalid_payload", "missing_peer_id", {"tx_type": env.tx_type})

    delta = payload.get("delta")
    peers["reputation_signals"].append(
        {
            "peer_id": peer_id,
            "delta": delta,
            "nonce": int(env.nonce),
            "payload": payload,
        }
    )
    return {"applied": "PEER_REPUTATION_SIGNAL", "peer_id": peer_id, "deduped": False}


# ---------------------------------------------------------------------------
# Router
# ---------------------------------------------------------------------------

def apply_networking(state: Json, env: TxEnvelope) -> Optional[Json]:
    t = str(getattr(env, "tx_type", "") or "").strip()

    if t == "PEER_ADVERTISE":
        return _apply_peer_advertise(state, env)

    if t == "PEER_RENDEZVOUS_TICKET_CREATE":
        return _apply_peer_rendezvous_ticket_create(state, env)
    if t == "PEER_RENDEZVOUS_TICKET_REVOKE":
        return _apply_peer_rendezvous_ticket_revoke(state, env)

    if t == "PEER_REQUEST_CONNECT":
        return _apply_peer_request_connect(state, env)

    if t == "PEER_BAN_SET":
        return _apply_peer_ban_set(state, env)
    if t == "PEER_REPUTATION_SIGNAL":
        return _apply_peer_reputation_signal(state, env)

    return None
