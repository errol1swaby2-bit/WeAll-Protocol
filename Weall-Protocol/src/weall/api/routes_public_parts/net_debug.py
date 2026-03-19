from __future__ import annotations

import os
from fastapi import HTTPException
from fastapi import APIRouter, Request

router = APIRouter()


class NetDebugConfigError(RuntimeError):
    """Raised when public net-debug config is malformed in prod."""


def _runtime_mode() -> str:
    if os.environ.get("PYTEST_CURRENT_TEST") and not os.environ.get("WEALL_MODE"):
        return "test"
    return str(os.environ.get("WEALL_MODE", "prod") or "prod").strip().lower() or "prod"


def _is_prod() -> bool:
    return _runtime_mode() == "prod"


def _env_bool(name: str, default: bool) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return bool(default)
    v = str(raw or "").strip()
    if v == "":
        return bool(default)
    vl = v.lower()
    if vl in {"1", "true", "yes", "y", "on"}:
        return True
    if vl in {"0", "false", "no", "n", "off"}:
        return False
    if _is_prod():
        raise NetDebugConfigError(f"invalid_boolean_env:{name}")
    return bool(default)


@router.get("/net/peers")
def v1_net_peers(request: Request) -> dict[str, object]:
    """
    Read-only mesh debug endpoint.

    NOTE:
      - This endpoint exposes *no secrets*.
      - It is still operationally sensitive (reveals peer topology / strikes / bans).
      - Consider restricting access at the reverse-proxy/WAF layer for public nodes.
    """

    # Fail-closed in production unless explicitly enabled.
    #
    # Default posture: public nodes should not expose topology/ban metadata.
    # Operators can opt-in via:
    #   WEALL_ENABLE_PUBLIC_DEBUG=1
    if _is_prod():
        allow = _env_bool("WEALL_ENABLE_PUBLIC_DEBUG", False)
        if not allow:
            raise HTTPException(status_code=404, detail="Not Found")

    net = getattr(request.app.state, "net_node", None)
    if net is None:
        return {
            "ok": True,
            "enabled": False,
            "reason": "net_node_not_running",
            "counts": {"peers_total": 0, "peers_established": 0, "peers_identity_verified": 0, "peers_banned": 0},
            "peers": [],
        }

    # Expect NetNode.peers_debug() (best-effort).
    try:
        dbg = net.peers_debug()
        if isinstance(dbg, dict):
            dbg["enabled"] = True
            return dbg
    except Exception:
        pass

    return {
        "ok": True,
        "enabled": True,
        "reason": "peers_debug_unavailable",
        "counts": {"peers_total": None, "peers_established": None, "peers_identity_verified": None, "peers_banned": None},
        "peers": [],
    }
