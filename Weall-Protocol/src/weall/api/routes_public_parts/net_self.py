from __future__ import annotations

import os
from typing import Any, Optional

from fastapi import APIRouter, Request

from weall.ledger.state import LedgerView

router = APIRouter()


def _env_bool(name: str, default: bool) -> bool:
    v = os.environ.get(name)
    if v is None:
        return bool(default)
    return (v or "").strip().lower() in {"1", "true", "yes", "y", "on"}


def _env_int(name: str, default: int) -> int:
    try:
        return int(str(os.environ.get(name, str(default))).strip())
    except Exception:
        return int(default)


def _env_str(name: str, default: str = "") -> str:
    v = os.environ.get(name)
    if v is None:
        return str(default)
    return str(v)


def _try_executor_snapshot(ex: Any) -> Optional[dict[str, Any]]:
    if ex is None:
        return None
    fn = getattr(ex, "snapshot", None)
    if not callable(fn):
        return None
    try:
        st = fn()
        return st if isinstance(st, dict) else None
    except Exception:
        return None


def _as_dict(x: Any) -> dict[str, Any]:
    return x if isinstance(x, dict) else {}


def _count_active_node_devices(acct: dict[str, Any]) -> int:
    devices = acct.get("devices")
    if not isinstance(devices, dict):
        return 0

    n = 0
    for did, rec_any in devices.items():
        if not isinstance(did, str) or not did:
            continue
        rec = _as_dict(rec_any)
        if not bool(rec.get("active", False)):
            continue

        d_type = str(rec.get("device_type") or rec.get("kind") or rec.get("type") or "").strip().lower()
        label = str(rec.get("label") or "").strip()
        is_node = (
            d_type == "node"
            or did.startswith("node:")
            or (label.lower().startswith("node") if label else False)
        )
        if is_node:
            n += 1
    return n


@router.get("/net/self")
def v1_net_self(request: Request) -> dict[str, object]:
    """
    Read-only mesh identity/self-report endpoint.

    SECURITY:
      - Never returns private key material.
      - Returns only operational metadata that helps validate a deployment.

    Consider restricting this endpoint at your reverse-proxy/WAF for public nodes.
    """
    app_state = request.app.state

    ex = getattr(app_state, "executor", None)
    st = _try_executor_snapshot(ex)

    chain_id = None
    node_id = None
    height = None
    tip = None
    if isinstance(st, dict):
        chain_id = st.get("chain_id")
        node_id = st.get("node_id")
        height = st.get("height")
        tip = st.get("tip")

    if not chain_id:
        chain_id = _env_str("WEALL_CHAIN_ID", "")
    if not node_id:
        node_id = _env_str("WEALL_NODE_ID", "")

    # --- NetNode presence ---
    net = getattr(app_state, "net_node", None)
    if net is None:
        net = getattr(app_state, "net", None)

    require_peer_identity = _env_bool("WEALL_NET_REQUIRE_PEER_IDENTITY", True)
    net_enabled = _env_bool("WEALL_NET_ENABLED", True)

    bind_host = _env_str("WEALL_NET_BIND_HOST", _env_str("WEALL_BIND_HOST", "0.0.0.0"))
    bind_port = _env_int("WEALL_NET_BIND_PORT", _env_int("WEALL_BIND_PORT", 30303))

    peers_env = _env_str("WEALL_PEERS", "")
    peers_list = [p.strip() for p in peers_env.split(",") if p.strip()] if peers_env else []

    node_pubkey_env = (_env_str("WEALL_NODE_PUBKEY", "") or "").strip() or None

    peer_id = None
    schema_version = None
    tx_index_hash = None
    cfg_pubkey = None

    try:
        cfg = getattr(net, "cfg", None)
        if cfg is not None:
            peer_id = getattr(cfg, "peer_id", None)
            schema_version = getattr(cfg, "schema_version", None)
            tx_index_hash = getattr(cfg, "tx_index_hash", None)
            cfg_pubkey = getattr(cfg, "identity_pubkey", None)
    except Exception:
        pass

    if not peer_id:
        peer_id = _env_str("WEALL_ACCOUNT_ID", "") or _env_str("WEALL_PEER_ID", "") or None

    # Peer counts (best-effort)
    connected_peers = None
    established_sessions = None
    try:
        t = getattr(net, "transport", None)
        if t is not None and hasattr(t, "connections"):
            connected_peers = len(list(t.connections()))  # type: ignore[call-arg]
    except Exception:
        connected_peers = None

    try:
        peer_ids_fn = getattr(net, "peer_ids", None)
        sess_fn = getattr(net, "session_is_established", None)
        if callable(peer_ids_fn) and callable(sess_fn):
            ids = list(peer_ids_fn())
            established_sessions = sum(1 for pid in ids if bool(sess_fn(pid)))
    except Exception:
        established_sessions = None

    # Startup warnings: node-device gate state (best-effort)
    warnings: list[str] = []
    node_device_count = None
    node_device_gate_ok = None
    if require_peer_identity and isinstance(st, dict) and peer_id:
        try:
            ledger = LedgerView.from_ledger(st)
            acct = getattr(ledger, "accounts", {}).get(peer_id)
            if isinstance(acct, dict):
                node_device_count = _count_active_node_devices(acct)
                node_device_gate_ok = (node_device_count == 1)
                if node_device_count == 0:
                    warnings.append("node_device_required: register ACCOUNT_DEVICE_REGISTER device_id 'node:<account_id>'")
                elif node_device_count > 1:
                    warnings.append("multiple_node_devices: revoke extras via ACCOUNT_DEVICE_REVOKE")
            else:
                warnings.append("account_not_found: create account before node can register node device")
        except Exception:
            warnings.append("node_device_gate_unknown: unable to read ledger snapshot")

    # Also warn if pubkey is missing while peer identity is required
    if require_peer_identity and not (cfg_pubkey or node_pubkey_env):
        warnings.append("missing_identity_pubkey: set WEALL_NODE_PUBKEY to participate in identity-gated mesh")

    return {
        "ok": True,
        "enabled": bool(net is not None) and bool(net_enabled),
        "chain": {
            "chain_id": chain_id or None,
            "node_id": node_id or None,
            "height": height if isinstance(height, int) else None,
            "tip": tip if isinstance(tip, str) else None,
        },
        "net": {
            "bind": {"host": bind_host, "port": int(bind_port)},
            "require_peer_identity": bool(require_peer_identity),
            "peer_id": peer_id,
            "schema_version": schema_version,
            "tx_index_hash": tx_index_hash,
            "identity_pubkey": (cfg_pubkey or node_pubkey_env),
            "peers_env": peers_list,
            "counts": {
                "connected_peers": connected_peers,
                "established_sessions": established_sessions,
            },
            "node_device_gate": {
                "active_node_device_count": node_device_count,
                "ok": node_device_gate_ok,
            },
        },
        "warnings": warnings,
        "notes": [
            "No private keys are returned by this endpoint.",
            "peer_id is intended to equal account_id (one node per user).",
        ],
    }
