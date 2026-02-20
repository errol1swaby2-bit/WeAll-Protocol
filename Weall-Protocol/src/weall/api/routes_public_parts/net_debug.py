from __future__ import annotations

import os
from fastapi import HTTPException
from fastapi import APIRouter, Request

router = APIRouter()


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
    mode = (os.environ.get("WEALL_MODE") or "prod").strip().lower()
    if mode == "prod":
        allow = (os.environ.get("WEALL_ENABLE_PUBLIC_DEBUG") or "").strip().lower()
        if allow not in {"1", "true", "yes", "y", "on"}:
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
