from __future__ import annotations

import os
import time
from typing import Any, Dict, List

from fastapi import APIRouter, Request

from weall.api.config import allow_insecure_localhost, normalize_base_url, read_nodes_registry

Json = Dict[str, Any]

router = APIRouter(tags=["nodes"])


class NodesEndpointConfigError(RuntimeError):
    """Raised when operator-supplied node registry/seed config is malformed in prod."""


class NodesEndpointStateError(RuntimeError):
    """Raised when local node state cannot be read safely in prod."""


def _runtime_mode() -> str:
    if os.environ.get("PYTEST_CURRENT_TEST") and not os.environ.get("WEALL_MODE"):
        return "test"
    return str(os.environ.get("WEALL_MODE", "prod") or "prod").strip().lower() or "prod"


def _is_prod() -> bool:
    return _runtime_mode() == "prod"


def _env_list(name: str) -> list[str]:
    raw = os.environ.get(name, "")
    parts = [p.strip() for p in raw.split(",")]
    return [p for p in parts if p]


def _validate_seed_url(base: str, *, allow_local: bool, source: str) -> str:
    try:
        return normalize_base_url(base, allow_insecure_localhost_urls=allow_local)
    except Exception as exc:
        if _is_prod():
            raise NodesEndpointConfigError(f"{source}_invalid_base_url") from exc
        raise


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
    strict = _is_prod()

    out: list[str] = []
    seen: set[str] = set()

    # 1) Registry file.
    reg = read_nodes_registry(getattr(cfg, "nodes_registry_path", None) if cfg is not None else None)
    nodes = reg.get("nodes", [])
    if isinstance(nodes, list):
        for n in nodes:
            if not isinstance(n, dict):
                if strict:
                    raise NodesEndpointConfigError("registry_node_not_object")
                continue
            base = n.get("base_url")
            if not isinstance(base, str):
                if strict:
                    raise NodesEndpointConfigError("registry_node_missing_base_url")
                continue
            try:
                norm = _validate_seed_url(base, allow_local=allow_local, source="registry_node")
            except NodesEndpointConfigError:
                raise
            except Exception:
                continue
            if norm not in seen:
                seen.add(norm)
                out.append(norm)

    # 2) Env seeds.
    for base in _env_list("WEALL_SEED_NODES"):
        try:
            norm = _validate_seed_url(base, allow_local=allow_local, source="seed_nodes")
        except NodesEndpointConfigError:
            raise
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
    strict = _is_prod()

    nodes: list[Json] = []
    # Preserve optional metadata from registry where possible.
    # If a seed came from env only, emit minimal metadata.
    reg_nodes = reg.get("nodes", [])
    meta_by_url: dict[str, Json] = {}
    if isinstance(reg_nodes, list):
        for n in reg_nodes:
            if not isinstance(n, dict):
                if strict:
                    raise NodesEndpointConfigError("registry_node_not_object")
                continue
            base = n.get("base_url")
            if not isinstance(base, str):
                if strict:
                    raise NodesEndpointConfigError("registry_node_missing_base_url")
                continue
            try:
                mode = getattr(cfg, "mode", "gateway") if cfg is not None else "gateway"
                allow_local = allow_insecure_localhost(str(mode))
                norm = _validate_seed_url(base, allow_local=allow_local, source="registry_node")
            except NodesEndpointConfigError:
                raise
            except Exception:
                continue

            role = n.get("role") if isinstance(n.get("role"), str) else "public"
            region = n.get("region") if isinstance(n.get("region"), str) else ""
            weight = n.get("weight")
            try:
                weight_i = int(weight) if weight is not None else 0
            except Exception as exc:
                if strict:
                    raise NodesEndpointConfigError("registry_node_bad_weight") from exc
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
    strict = _is_prod()

    try:
        raw_peer_ids = list(net_node.peer_ids())
    except Exception as exc:
        if strict:
            raise NodesEndpointStateError("nodes_known_peer_ids_failed") from exc
        raw_peer_ids = []

    peer_ids: list[str] = []
    for pid in raw_peer_ids:
        if not isinstance(pid, str) or not pid:
            if strict:
                raise NodesEndpointStateError("nodes_known_bad_peer_id")
            continue
        peer_ids.append(pid)

    # If the node exposes richer session objects, include them best-effort.
    sessions = getattr(net_node, "_peers", None)
    if strict and sessions is not None and not isinstance(sessions, dict):
        raise NodesEndpointStateError("nodes_known_sessions_not_dict")
    for pid in peer_ids[:200]:  # hard cap to avoid huge payloads
        rec: Json = {"peer_id": str(pid)}
        if isinstance(sessions, dict):
            ps = sessions.get(pid)
            if ps is not None:
                addr = getattr(ps, "addr", None)
                uri = getattr(addr, "uri", None)
                if uri is not None and not isinstance(uri, str):
                    if strict:
                        raise NodesEndpointStateError("nodes_known_bad_peer_uri")
                if isinstance(uri, str) and uri:
                    rec["addr"] = uri
                rec["established"] = bool(getattr(ps, "established", False))
                last_seen_ms = getattr(ps, "last_seen_ms", None)
                if last_seen_ms is not None and not isinstance(last_seen_ms, int):
                    if strict:
                        raise NodesEndpointStateError("nodes_known_bad_last_seen")
                if isinstance(last_seen_ms, int):
                    rec["last_seen_ms"] = last_seen_ms
                rec["identity_verified"] = bool(getattr(ps, "identity_verified", False))
                acct = getattr(ps, "account_id", None)
                if acct is not None and not isinstance(acct, str):
                    if strict:
                        raise NodesEndpointStateError("nodes_known_bad_account_id")
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
