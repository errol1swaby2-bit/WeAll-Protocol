from __future__ import annotations

import os
import time
from typing import Any, Dict, List

from fastapi import APIRouter, Request

from weall.api.config import allow_insecure_localhost, normalize_base_url, read_nodes_registry

Json = Dict[str, Any]

router = APIRouter(tags=["nodes"])


def _env_list(name: str) -> list[str]:
    raw = os.environ.get(name, "")
    parts = [p.strip() for p in raw.split(",")]
    return [p for p in parts if p]


def _load_seed_urls(request: Request) -> list[str]:
    """Return seed base URLs from both registry file and env.

    Sources (merged, de-duped):
      1) JSON registry file at cfg.nodes_registry_path
      2) WEALL_SEED_NODES env (comma-separated)

    Validation:
      - https:// only
      - optionally allow http://localhost + http://127.0.0.1 when configured
    """
    cfg = getattr(request.app.state, "cfg", None)
    mode = getattr(cfg, "mode", "gateway") if cfg is not None else "gateway"
    allow_local = allow_insecure_localhost(str(mode))

    out: list[str] = []
    seen: set[str] = set()

    # 1) Registry file.
    reg = read_nodes_registry(getattr(cfg, "nodes_registry_path", None) if cfg is not None else None)
    nodes = reg.get("nodes", [])
    if isinstance(nodes, list):
        for n in nodes:
            if not isinstance(n, dict):
                continue
            base = n.get("base_url")
            if not isinstance(base, str):
                continue
            try:
                norm = normalize_base_url(base, allow_insecure_localhost_urls=allow_local)
            except Exception:
                continue
            if norm not in seen:
                seen.add(norm)
                out.append(norm)

    # 2) Env seeds.
    for base in _env_list("WEALL_SEED_NODES"):
        try:
            norm = normalize_base_url(base, allow_insecure_localhost_urls=allow_local)
        except Exception:
            continue
        if norm not in seen:
            seen.add(norm)
            out.append(norm)

    return out


def _seeds_response(request: Request) -> Json:
    cfg = getattr(request.app.state, "cfg", None)
    reg = read_nodes_registry(getattr(cfg, "nodes_registry_path", None) if cfg is not None else None)
    version = int(reg.get("version", 1) or 1)
    seeds = _load_seed_urls(request)

    nodes: list[Json] = []
    # Preserve optional metadata from registry where possible.
    # If a seed came from env only, emit minimal metadata.
    reg_nodes = reg.get("nodes", [])
    meta_by_url: dict[str, Json] = {}
    if isinstance(reg_nodes, list):
        for n in reg_nodes:
            if not isinstance(n, dict):
                continue
            base = n.get("base_url")
            if not isinstance(base, str):
                continue
            try:
                mode = getattr(cfg, "mode", "gateway") if cfg is not None else "gateway"
                allow_local = allow_insecure_localhost(str(mode))
                norm = normalize_base_url(base, allow_insecure_localhost_urls=allow_local)
            except Exception:
                continue

            role = n.get("role") if isinstance(n.get("role"), str) else "public"
            region = n.get("region") if isinstance(n.get("region"), str) else ""
            weight = n.get("weight")
            try:
                weight_i = int(weight) if weight is not None else 0
            except Exception:
                weight_i = 0

            meta_by_url[norm] = {"base_url": norm, "role": role, "region": region, "weight": weight_i}

    for url in seeds:
        meta = meta_by_url.get(url) or {"base_url": url, "role": "seed", "region": "", "weight": 0}
        nodes.append(meta)

    return {
        "ok": True,
        "version": version,
        "generated_ts_ms": int(time.time() * 1000),
        "nodes": nodes,
    }


def _known_peers_response(request: Request) -> Json:
    """Return a sanitized view of peers currently known/connected to this node."""
    net_node = getattr(request.app.state, "net_node", None)
    if net_node is None:
        return {"ok": True, "generated_ts_ms": int(time.time() * 1000), "peers": []}

    peers: List[Json] = []

    peer_ids = []
    try:
        peer_ids = list(net_node.peer_ids())
    except Exception:
        peer_ids = []

    # If the node exposes richer session objects, include them best-effort.
    sessions = getattr(net_node, "_peers", None)
    for pid in peer_ids[:200]:  # hard cap to avoid huge payloads
        rec: Json = {"peer_id": str(pid)}
        if isinstance(sessions, dict):
            ps = sessions.get(pid)
            if ps is not None:
                addr = getattr(ps, "addr", None)
                uri = getattr(addr, "uri", None)
                if isinstance(uri, str) and uri:
                    rec["addr"] = uri
                rec["established"] = bool(getattr(ps, "established", False))
                last_seen_ms = getattr(ps, "last_seen_ms", None)
                if isinstance(last_seen_ms, int):
                    rec["last_seen_ms"] = last_seen_ms
                rec["identity_verified"] = bool(getattr(ps, "identity_verified", False))
                acct = getattr(ps, "account_id", None)
                if isinstance(acct, str) and acct:
                    rec["account_id"] = acct

        peers.append(rec)

    return {"ok": True, "generated_ts_ms": int(time.time() * 1000), "peers": peers}


@router.get("/v1/nodes")
def v1_nodes(request: Request) -> Json:
    """Backwards-compatible endpoint.

    Historically this path returned a gateway-managed seed registry.
    For Route B, we keep it but make it explicitly return the seed list.
    """
    return _seeds_response(request)


@router.get("/v1/nodes/seeds")
def v1_nodes_seeds(request: Request) -> Json:
    """Bootstrap seeds: operator-configured list + optional registry file."""
    return _seeds_response(request)


@router.get("/v1/nodes/known")
def v1_nodes_known(request: Request) -> Json:
    """Node-local peer view.

    Returns connected peers (best-effort), not a global directory.
    """
    return _known_peers_response(request)
