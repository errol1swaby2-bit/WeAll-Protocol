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
from typing import Any

from weall.runtime.tx_admission import TxEnvelope

Json = dict[str, Any]


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




def _account_record(state: Json, account_id: str) -> Json:
    accounts = state.get("accounts")
    if not isinstance(accounts, dict):
        return {}
    rec = accounts.get(account_id)
    return rec if isinstance(rec, dict) else {}


def _active_node_devices_for_account(state: Json, account_id: str) -> dict[str, Json]:
    account = _account_record(state, account_id)
    devices = account.get("devices")
    by_id = devices.get("by_id") if isinstance(devices, dict) else None
    out: dict[str, Json] = {}
    if not isinstance(by_id, dict):
        return out
    for device_id_raw, rec_any in by_id.items():
        device_id = _as_str(device_id_raw).strip()
        rec = _as_dict(rec_any)
        if not device_id or bool(rec.get("revoked", False)):
            continue
        if _as_str(rec.get("device_type")).strip().lower() != "node":
            continue
        pubkey = _as_str(rec.get("pubkey")).strip()
        if not pubkey:
            continue
        out[device_id] = rec
    return out


def _allowed_peer_ids_for_node(account_id: str, device_id: str, node_pubkey: str) -> set[str]:
    return {
        account_id,
        device_id,
        node_pubkey,
        f"node:{account_id}:{node_pubkey[:16]}",
    }


def _require_node_advertisement_binding(state: Json, env: TxEnvelope, payload: Json, peer_id: str) -> tuple[str, str]:
    """Require PEER_ADVERTISE to be bound to an active account node device.

    Peer advertisements are consensus-visible discovery records.  They do not
    grant validator or service authority, but they must not allow an account to
    publish arbitrary peer IDs/endpoints that look like another node.  The
    binding accepted here is deliberately simple and deterministic: the signer
    must already have an active ACCOUNT_DEVICE_REGISTER record with
    device_type=node, and the advertised peer_id must be one of the stable IDs
    derived from that account/device/pubkey.
    """

    account_id = _as_str(getattr(env, "signer", "")).strip()
    if not account_id:
        raise NetworkingApplyError("invalid_tx", "missing_signer", {"tx_type": env.tx_type})

    devices = _active_node_devices_for_account(state, account_id)
    if not devices:
        raise NetworkingApplyError(
            "forbidden",
            "node_device_required_for_peer_advertise",
            {"account_id": account_id},
        )

    requested_device_id = _as_str(_pick(payload, "device_id", "node_device_id")).strip()
    requested_pubkey = _as_str(_pick(payload, "node_pubkey", "node_public_key", "pubkey")).strip()

    candidates: list[tuple[str, Json]] = []
    for device_id, rec in sorted(devices.items()):
        pubkey = _as_str(rec.get("pubkey")).strip()
        if requested_device_id and requested_device_id != device_id:
            continue
        if requested_pubkey and requested_pubkey != pubkey:
            continue
        candidates.append((device_id, rec))

    if not candidates:
        raise NetworkingApplyError(
            "forbidden",
            "node_key_not_registered_for_peer_advertise",
            {
                "account_id": account_id,
                "device_id": requested_device_id,
                "node_pubkey": requested_pubkey,
            },
        )

    if len(candidates) > 1 and not (requested_device_id or requested_pubkey):
        raise NetworkingApplyError(
            "invalid_payload",
            "ambiguous_node_device_for_peer_advertise",
            {"account_id": account_id, "candidate_count": len(candidates)},
        )

    device_id, rec = candidates[0]
    node_pubkey = _as_str(rec.get("pubkey")).strip()
    allowed_peer_ids = _allowed_peer_ids_for_node(account_id, device_id, node_pubkey)
    if peer_id not in allowed_peer_ids:
        raise NetworkingApplyError(
            "forbidden",
            "peer_id_not_bound_to_node_key",
            {
                "account_id": account_id,
                "peer_id": peer_id,
                "allowed_peer_ids": sorted(allowed_peer_ids),
            },
        )
    return device_id, node_pubkey

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


def _require_connect_request_node_binding(state: Json, env: TxEnvelope) -> tuple[str, ...]:
    """Require PEER_REQUEST_CONNECT to be authored by a registered node device.

    A connect request is not consensus authority, but it is still public peer
    intent.  Requiring an active node device prevents ordinary account keys or
    spoofed signer/account pairs from polluting peer-request state during
    onboarding and promotion.
    """

    signer = _as_str(env.signer).strip()
    if not signer:
        raise NetworkingApplyError("invalid_payload", "missing_signer", {"tx_type": env.tx_type})
    devices = _active_node_devices_for_account(state, signer)
    if not devices:
        raise NetworkingApplyError(
            "forbidden",
            "peer_request_connect_requires_registered_node_device",
            {"tx_type": env.tx_type, "account_id": signer},
        )
    return tuple(sorted(_as_str(rec.get("pubkey")).strip() for rec in devices.values() if _as_str(rec.get("pubkey")).strip()))


def _endpoint_is_plausible(endpoint: str) -> bool:
    endpoint = endpoint.strip()
    if not endpoint or len(endpoint) > 2048:
        return False
    # Keep this deterministic and intentionally syntax-light: consensus records
    # connection intent, while the networking layer performs live reachability.
    # The goal here is to reject opaque garbage, not to do DNS/HTTP validation.
    lowered = endpoint.lower()
    allowed_prefixes = ("http://", "https://", "ws://", "wss://", "tcp://", "weall://", "relay://")
    return lowered.startswith(allowed_prefixes)


def _has_advertised_peer(peers: Json, peer_id: str) -> bool:
    if not peer_id:
        return False
    ads = peers.get("ads")
    if not isinstance(ads, dict):
        return False
    for rec_any in ads.values():
        rec = _as_dict(rec_any)
        if _as_str(rec.get("peer_id")).strip() == peer_id:
            return True
    return False


# ---------------------------------------------------------------------------
# PEER_ADVERTISE
# ---------------------------------------------------------------------------


def _apply_peer_advertise(state: Json, env: TxEnvelope) -> Json:
    peers = _ensure_peers(state)
    payload = _as_dict(env.payload)

    endpoint = _as_str(_pick(payload, "endpoint", "url")).strip()
    if not endpoint:
        raise NetworkingApplyError("invalid_payload", "missing_endpoint", {"tx_type": env.tx_type})

    peer_id = _as_str(_pick(payload, "peer_id", "peer", "id") or env.signer).strip()
    if not peer_id:
        raise NetworkingApplyError("invalid_payload", "missing_peer_id", {"tx_type": env.tx_type})

    device_id, node_pubkey = _require_node_advertisement_binding(state, env, payload, peer_id)

    ads = peers["ads"]
    rec = ads.get(env.signer)
    deduped = (
        isinstance(rec, dict)
        and rec.get("endpoint") == endpoint
        and rec.get("peer_id") == peer_id
        and rec.get("node_pubkey") == node_pubkey
        and rec.get("device_id") == device_id
    )

    rec = {
        "account_id": env.signer,
        "peer_id": peer_id,
        "endpoint": endpoint,
        "device_id": device_id,
        "node_pubkey": node_pubkey,
        "nonce": int(env.nonce),
        "payload": payload,
    }
    ads[env.signer] = rec
    return {
        "applied": "PEER_ADVERTISE",
        "account_id": env.signer,
        "peer_id": peer_id,
        "device_id": device_id,
        "node_pubkey": node_pubkey,
        "deduped": deduped,
    }


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

    node_pubkeys = _require_connect_request_node_binding(state, env)

    to_peer_id = _as_str(_pick(payload, "peer_id", "to_peer_id", "target_peer_id")).strip()
    endpoint = _as_str(_pick(payload, "endpoint", "url")).strip()
    ticket_id = _as_str(_pick(payload, "ticket_id", "rendezvous_ticket_id")).strip()

    # Allow one of: a live endpoint, an active rendezvous ticket, or a peer id
    # already advertised in protocol state.  This preserves bootstrap use where
    # the observer requests the genesis API endpoint directly, but it rejects
    # pure arbitrary peer-id pollution.
    if not to_peer_id and not endpoint and not ticket_id:
        raise NetworkingApplyError("invalid_payload", "missing_target", {"tx_type": env.tx_type})

    if endpoint and not _endpoint_is_plausible(endpoint):
        raise NetworkingApplyError(
            "invalid_payload",
            "invalid_endpoint",
            {"tx_type": env.tx_type, "endpoint": endpoint},
        )

    if ticket_id:
        ticket = _as_dict(_as_dict(peers.get("tickets")).get(ticket_id))
        if not ticket or bool(ticket.get("revoked", False)) or _as_str(ticket.get("status")).lower() != "active":
            raise NetworkingApplyError(
                "forbidden",
                "peer_request_connect_requires_active_rendezvous_ticket",
                {"tx_type": env.tx_type, "ticket_id": ticket_id},
            )

    if to_peer_id and not endpoint and not ticket_id and not _has_advertised_peer(peers, to_peer_id):
        raise NetworkingApplyError(
            "forbidden",
            "peer_request_connect_target_not_advertised",
            {"tx_type": env.tx_type, "peer_id": to_peer_id},
        )

    peers["connect_requests"].append(
        {
            "from": env.signer,
            "from_node_pubkeys": list(node_pubkeys),
            "to_peer_id": to_peer_id or None,
            "endpoint": endpoint or None,
            "ticket_id": ticket_id or None,
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


def apply_networking(state: Json, env: TxEnvelope) -> Json | None:
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
