from __future__ import annotations

import ipaddress
import os
from urllib.parse import urlparse
from typing import Any

from fastapi import APIRouter, Request

from weall.ledger.state import LedgerView

router = APIRouter()


class NetSelfConfigError(RuntimeError):
    """Raised when operator-supplied net/self config is malformed in prod."""


class NetSelfStateError(RuntimeError):
    """Raised when net/self cannot read local runtime state safely in prod."""


def _runtime_mode() -> str:
    if os.environ.get("PYTEST_CURRENT_TEST") and not os.environ.get("WEALL_MODE"):
        return "test"
    return str(os.environ.get("WEALL_MODE", "prod") or "prod").strip().lower() or "prod"


def _is_prod() -> bool:
    return _runtime_mode() == "prod"


def _env_bool(name: str, default: bool) -> bool:
    v = os.environ.get(name)
    if v is None:
        return bool(default)
    return (v or "").strip().lower() in {"1", "true", "yes", "y", "on"}


def _env_int(name: str, default: int) -> int:
    raw = os.environ.get(name)
    if raw is None:
        return int(default)
    try:
        return int(str(raw).strip())
    except Exception as exc:
        if _is_prod():
            raise NetSelfConfigError(f"invalid_integer_env:{name}") from exc
        return int(default)


def _env_str(name: str, default: str = "") -> str:
    v = os.environ.get(name)
    if v is None:
        return str(default)
    return str(v)


def _split_csv(raw: str) -> list[str]:
    return [p.strip() for p in str(raw or "").split(",") if p.strip()]


def _host_kind(host: str) -> str:
    h = str(host or "").strip().lower().strip("[]")
    if not h:
        return "missing"
    if h in {"0.0.0.0", "::", "*"}:
        return "unspecified"
    if h in {"localhost", "localhost.localdomain"}:
        return "loopback"
    try:
        ip = ipaddress.ip_address(h)
    except ValueError:
        # A DNS name may be public or private depending on operator DNS. Treat it
        # as an operator claim that must be proven by runtime peer/session counts.
        return "dns"
    if ip.is_loopback:
        return "loopback"
    if ip.is_private or ip.is_link_local or ip.is_reserved or ip.is_multicast:
        return "private"
    return "public_ip"


def _advertise_uri_status(uri: str | None) -> dict[str, object]:
    raw = str(uri or "").strip()
    if not raw:
        return {
            "configured": False,
            "status": "missing",
            "host_kind": "missing",
            "dialable_public_claim": False,
        }
    parsed = urlparse(raw)
    scheme = str(parsed.scheme or "").lower()
    if scheme not in {"tcp", "tls"}:
        return {
            "configured": True,
            "status": "unsupported_scheme",
            "scheme": scheme or None,
            "host": parsed.hostname or None,
            "host_kind": _host_kind(parsed.hostname or ""),
            "dialable_public_claim": False,
        }
    kind = _host_kind(parsed.hostname or "")
    public_claim = kind in {"public_ip", "dns"}
    status = "public_or_dns" if public_claim else kind
    return {
        "configured": True,
        "status": status,
        "scheme": scheme,
        "host": parsed.hostname or None,
        "port": int(parsed.port) if parsed.port is not None else None,
        "host_kind": kind,
        "dialable_public_claim": bool(public_claim),
    }


def _nat_traversal_report(
    *,
    bind_host: str,
    bind_port: int,
    advertise_uri: str | None,
    connected_peers: int | None,
    established_sessions: int | None,
) -> dict[str, object]:
    mode = (_env_str("WEALL_NET_NAT_MODE", "auto") or "auto").strip().lower()
    if mode not in {"auto", "public_inbound", "behind_nat", "relay_only", "local_only"}:
        mode = "auto"

    public_testnet = _env_bool("WEALL_PUBLIC_TESTNET", False)
    validator_intent = (
        _env_bool("WEALL_VALIDATOR_SIGNING_ENABLED", False)
        or _env_bool("WEALL_BFT_ENABLED", False)
        or (_env_str("WEALL_NODE_LIFECYCLE_STATE", "").strip().lower() in {"validator", "production_validator", "validator_candidate"})
    )
    seed_intent = _env_bool("WEALL_PUBLIC_TESTNET_SEED_NODE", False) or _env_bool("WEALL_SEED_NODE", False)
    inbound_required = _env_bool("WEALL_NET_INBOUND_REQUIRED", bool(seed_intent or validator_intent))

    adv = _advertise_uri_status(advertise_uri)
    relay_urls = _split_csv(_env_str("WEALL_NET_RELAY_URLS", ""))
    relay_recipients = _split_csv(_env_str("WEALL_NET_RELAY_RECIPIENTS", ""))
    relay_pubkeys_raw = _env_str("WEALL_NET_RELAY_RECIPIENT_PUBKEYS", "").strip()
    relay_client_enabled = _env_bool("WEALL_NET_RELAY_CLIENT_ENABLED", False)
    relay_server_enabled = _env_bool("WEALL_NET_RELAY_ENABLED", False)
    relay_ready = bool(relay_client_enabled and relay_urls and (relay_recipients or not public_testnet) and relay_pubkeys_raw)

    bind_kind = _host_kind(bind_host)
    inbound_public_claim = bool(adv.get("dialable_public_claim"))
    if mode == "auto":
        if inbound_public_claim:
            recommended = "public_inbound"
        elif relay_client_enabled:
            recommended = "outbound_relay_only"
        elif bind_kind in {"loopback", "private"}:
            recommended = "local_or_lan_only"
        else:
            recommended = "needs_advertise_or_relay"
    else:
        recommended = mode

    warnings: list[str] = []
    actions: list[str] = []
    if inbound_required and not inbound_public_claim:
        warnings.append("inbound_required_without_public_advertise_uri")
        actions.append("Set WEALL_NET_ADVERTISE_URI=tcp://<public-host-or-dns>:<p2p-port> or run this node as relay-only observer instead of seed/validator.")
    if public_testnet and not inbound_public_claim and not relay_client_enabled and not relay_server_enabled:
        warnings.append("public_testnet_no_public_advertise_or_relay")
        actions.append("For a firewalled observer, enable WEALL_NET_RELAY_CLIENT_ENABLED=1 with WEALL_NET_RELAY_URLS and recipient pubkey binding.")
    if relay_client_enabled and not relay_urls:
        warnings.append("relay_client_enabled_without_urls")
        actions.append("Set WEALL_NET_RELAY_URLS to one or more HTTPS relay/base API URLs.")
    if relay_client_enabled and not relay_pubkeys_raw and _is_prod():
        warnings.append("relay_client_missing_recipient_pubkey_binding")
        actions.append("Set WEALL_NET_RELAY_RECIPIENT_PUBKEYS so relay fetches are recipient-key bound.")
    if adv.get("configured") and not inbound_public_claim:
        warnings.append(f"advertise_uri_not_public:{adv.get('status')}")
        actions.append("Do not publish loopback, private, or unspecified advertise URIs in public seed/validator records.")
    if connected_peers == 0 and established_sessions == 0 and (public_testnet or relay_client_enabled or inbound_public_claim):
        warnings.append("no_established_mesh_peers")
        actions.append("Check seed reachability, outbound firewall, P2P port forwarding, TLS certificate/reverse proxy, and relay status.")

    return {
        "mode": mode,
        "recommended_profile": recommended,
        "public_testnet": bool(public_testnet),
        "inbound_required": bool(inbound_required),
        "bind": {
            "host": bind_host,
            "port": int(bind_port),
            "host_kind": bind_kind,
            "is_unspecified": bind_kind == "unspecified",
        },
        "advertise": adv,
        "inbound_reachable_claim": bool(inbound_public_claim),
        "relay": {
            "server_enabled": bool(relay_server_enabled),
            "client_enabled": bool(relay_client_enabled),
            "urls_configured": len(relay_urls),
            "recipients_configured": len(relay_recipients),
            "recipient_pubkeys_configured": bool(relay_pubkeys_raw),
            "client_ready": bool(relay_ready),
            "authority": "transport_only",
        },
        "mesh_counts": {
            "connected_peers": connected_peers,
            "established_sessions": established_sessions,
        },
        "warnings": warnings,
        "recovery_actions": actions,
        "authority": "network_transport_only",
    }


def _try_executor_state(ex: Any) -> dict[str, Any] | None:
    if ex is None:
        return None
    fn = getattr(ex, "read_state", None)
    if not callable(fn):
        if _is_prod():
            raise NetSelfStateError("net_self_state_reader_missing")
        return None
    try:
        st = fn()
    except Exception as exc:
        if _is_prod():
            raise NetSelfStateError("net_self_state_read_failed") from exc
        return None
    if st is None:
        return None
    if not isinstance(st, dict):
        if _is_prod():
            raise NetSelfStateError("net_self_state_not_dict")
        return None
    return st


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

        d_type = (
            str(rec.get("device_type") or rec.get("kind") or rec.get("type") or "").strip().lower()
        )
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
    st = _try_executor_state(ex)

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

    # Publicly reachable address to give other nodes.
    # Bind host is often 0.0.0.0 and not directly dialable.
    advertise_uri = (
        _env_str("WEALL_NET_ADVERTISE_URI", "") or _env_str("WEALL_NET_PUBLIC_URI", "")
    ).strip() or None

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
    except Exception as exc:
        if _is_prod():
            raise NetSelfStateError("net_self_cfg_read_failed") from exc

    if not peer_id:
        peer_id = _env_str("WEALL_ACCOUNT_ID", "") or _env_str("WEALL_PEER_ID", "") or None

    # Peer counts (best-effort)
    connected_peers = None
    established_sessions = None
    seed_discovery: dict[str, Any] | None = None
    try:
        t = getattr(net, "transport", None)
        if t is not None and hasattr(t, "connections"):
            connected_peers = len(list(t.connections()))  # type: ignore[call-arg]
    except Exception as exc:
        if _is_prod() and net is not None:
            raise NetSelfStateError("net_self_connections_failed") from exc
        connected_peers = None

    try:
        peer_ids_fn = getattr(net, "peer_ids", None)
        sess_fn = getattr(net, "session_is_established", None)
        if callable(peer_ids_fn) and callable(sess_fn):
            ids = list(peer_ids_fn())
            established_sessions = sum(1 for pid in ids if bool(sess_fn(pid)))
    except Exception as exc:
        if _is_prod() and net is not None:
            raise NetSelfStateError("net_self_sessions_failed") from exc
        established_sessions = None

    try:
        loop = getattr(app_state, "net_loop", None)
        seed_fn = getattr(loop, "seed_discovery_debug", None)
        if callable(seed_fn):
            maybe_seed = seed_fn()
            if isinstance(maybe_seed, dict):
                seed_discovery = maybe_seed
    except Exception as exc:
        if _is_prod():
            raise NetSelfStateError("net_self_seed_discovery_failed") from exc
        seed_discovery = None

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
                node_device_gate_ok = node_device_count == 1
                if node_device_count == 0:
                    warnings.append(
                        "node_device_required: register ACCOUNT_DEVICE_REGISTER device_id 'node:<account_id>'"
                    )
                elif node_device_count > 1:
                    warnings.append(
                        "multiple_node_devices: revoke extras via ACCOUNT_DEVICE_REVOKE"
                    )
            else:
                warnings.append(
                    "account_not_found: create account before node can register node device"
                )
        except Exception:
            warnings.append("node_device_gate_unknown: unable to read ledger state")

    # Also warn if pubkey is missing while peer identity is required
    if require_peer_identity and not (cfg_pubkey or node_pubkey_env):
        warnings.append(
            "missing_identity_pubkey: set WEALL_NODE_PUBKEY to participate in identity-gated mesh"
        )

    nat = _nat_traversal_report(
        bind_host=bind_host,
        bind_port=int(bind_port),
        advertise_uri=advertise_uri,
        connected_peers=connected_peers if isinstance(connected_peers, int) else None,
        established_sessions=established_sessions if isinstance(established_sessions, int) else None,
    )
    for warning in nat.get("warnings", []):
        if isinstance(warning, str) and warning not in warnings:
            warnings.append(warning)

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
            "advertise_uri": advertise_uri,
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
            "seed_discovery": seed_discovery,
            "nat": nat,
        },
        "nat": nat,
        "warnings": warnings,
        "notes": [
            "No private keys are returned by this endpoint.",
            "peer_id is intended to equal account_id (one node per user).",
            "advertise_uri should be the dialable public URI if this node accepts inbound peers.",
        ],
    }
