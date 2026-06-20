from __future__ import annotations

import os
import time
from typing import Any
from weall.api.errors import ApiError

from fastapi import APIRouter, Request

from weall.api.config import allow_insecure_localhost, normalize_base_url, read_nodes_registry
from weall.api.public_seed_registry import (
    PublicSeedRegistryError,
    commitment_payload,
    load_public_seed_registry,
    public_seed_registry_path,
    public_testnet_enabled,
)

Json = dict[str, Any]

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


def _public_mode() -> bool:
    return public_testnet_enabled()


def _public_seed_api_error(exc: PublicSeedRegistryError) -> ApiError:
    return ApiError.service_unavailable(
        str(exc) or "public_seed_registry_error",
        "public testnet seed registry is missing or unsafe",
        {"public_testnet": True, "recovery": "configure WEALL_PUBLIC_TESTNET_SEED_REGISTRY_PATH with a valid public seed registry"},
    )


def _load_public_registry_for_request(request: Request) -> Json:
    cfg = getattr(request.app.state, "cfg", None)
    path = public_seed_registry_path(getattr(cfg, "public_seed_registry_path", None) if cfg is not None else None)
    try:
        return load_public_seed_registry(path)
    except PublicSeedRegistryError as exc:
        raise _public_seed_api_error(exc)


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
    if _public_mode():
        registry = _load_public_registry_for_request(request)
        return [str(url) for url in registry.get("seed_api_urls", []) if str(url).strip()]

    cfg = getattr(request.app.state, "cfg", None)
    mode = getattr(cfg, "mode", "gateway") if cfg is not None else "gateway"
    allow_local = allow_insecure_localhost(str(mode))
    strict = _is_prod()

    out: list[str] = []
    seen: set[str] = set()

    # 1) Registry file.
    reg = read_nodes_registry(
        getattr(cfg, "nodes_registry_path", None) if cfg is not None else None
    )
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

    if _public_mode():
        registry = _load_public_registry_for_request(request)
        nodes = [dict(n) for n in registry.get("nodes", []) if isinstance(n, dict)]
        commitments = commitment_payload(registry)
        return {
            "ok": True,
            "version": int(registry.get("version", 1) or 1),
            "public_testnet": True,
            "generated_ts_ms": int(time.time() * 1000),
            "network_id": registry.get("network_id", ""),
            "chain_id": registry.get("chain_id", ""),
            "genesis_hash": registry.get("genesis_hash", ""),
            "protocol_profile_hash": registry.get("protocol_profile_hash", ""),
            "tx_index_hash": registry.get("tx_index_hash", ""),
            "commitments": commitments,
            "seed_p2p_urls": registry.get("seed_p2p_urls", []),
            "seed_registry_signature": registry.get("seed_registry_signature", ""),
            "seed_registry_signer": registry.get("seed_registry_signer", ""),
            "seed_registry_signature_status": registry.get("seed_registry_signature_status", {}),
            "active_validator_endpoint_policy": registry.get("active_validator_endpoint_policy", "verified_or_hint"),
            "resettable_testnet": True,
            "economics_active": False,
            "nodes": nodes,
        }

    reg = read_nodes_registry(
        getattr(cfg, "nodes_registry_path", None) if cfg is not None else None
    )
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

            meta_by_url[norm] = {
                "base_url": norm,
                "role": role,
                "region": region,
                "weight": weight_i,
            }

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

    peers: list[Json] = []
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




def _try_read_state(request: Request) -> Json:
    ex = getattr(request.app.state, "executor", None)
    fn = getattr(ex, "read_state", None)
    if callable(fn):
        try:
            out = fn()
            if isinstance(out, dict):
                return out
        except Exception:
            if _is_prod():
                raise NodesEndpointStateError("nodes_validators_state_read_failed")
    return {}


def _active_validators_from_state(state: Json) -> list[str]:
    values: list[str] = []
    validators_root = state.get("validators")
    if isinstance(validators_root, dict):
        active_set = validators_root.get("active_set") or validators_root.get("active")
        if isinstance(active_set, list):
            values.extend(str(v).strip() for v in active_set if str(v).strip())
        registry = validators_root.get("registry")
        if isinstance(registry, dict):
            for key, rec in registry.items():
                if isinstance(rec, dict) and bool(rec.get("active", False)):
                    values.append(str(rec.get("account_id") or rec.get("account") or key).strip())
    roles = state.get("roles")
    if isinstance(roles, dict):
        validators = roles.get("validators")
        if isinstance(validators, dict):
            active_set = validators.get("active_set")
            if isinstance(active_set, list):
                values.extend(str(v).strip() for v in active_set if str(v).strip())
            by_id = validators.get("by_id")
            if isinstance(by_id, dict):
                for key, rec in by_id.items():
                    if isinstance(rec, dict) and bool(rec.get("active", False)):
                        values.append(str(rec.get("account_id") or key).strip())
    return sorted({v for v in values if v})


def _validator_record_from_state(state: Json, account_id: str) -> Json:
    roles = state.get("roles") if isinstance(state.get("roles"), dict) else {}
    validators = roles.get("validators") if isinstance(roles.get("validators"), dict) else {}
    by_id = validators.get("by_id") if isinstance(validators.get("by_id"), dict) else {}
    rec = by_id.get(account_id) if isinstance(by_id, dict) else None
    if not isinstance(rec, dict):
        root = state.get("validators") if isinstance(state.get("validators"), dict) else {}
        registry = root.get("registry") if isinstance(root.get("registry"), dict) else {}
        rec = registry.get(account_id) if isinstance(registry, dict) else None
    return dict(rec) if isinstance(rec, dict) else {}


def _registry_validator_endpoints(request: Request) -> list[Json]:
    if not _public_mode():
        return []
    registry = _load_public_registry_for_request(request)
    endpoints = registry.get("validator_endpoints", [])
    return [dict(e) for e in endpoints if isinstance(e, dict)]




def _validator_endpoint_max_age_ms() -> int:
    raw = str(os.environ.get("WEALL_PUBLIC_VALIDATOR_ENDPOINT_MAX_AGE_MS") or "3600000").strip()
    try:
        value = int(raw)
    except Exception:
        value = 3_600_000
    return max(60_000, value)


def _endpoint_freshness(ep: Json, *, now_ms: int, max_age_ms: int) -> Json:
    ts = 0
    for key in ("proof_timestamp_ms", "last_seen_ms"):
        try:
            ts = int(ep.get(key) or 0)
        except Exception:
            ts = 0
        if ts > 0:
            break
    age_ms = now_ms - ts if ts > 0 else None
    stale = ts <= 0 or (age_ms is not None and age_ms > max_age_ms)
    return {
        "proof_timestamp_ms": ts,
        "age_ms": age_ms,
        "max_age_ms": max_age_ms,
        "fresh": not stale,
        "stale": stale,
        "reason": "missing_timestamp" if ts <= 0 else ("stale" if stale else "fresh"),
    }

def _validator_endpoints_response(request: Request) -> Json:
    state = _try_read_state(request)
    active_validators = _active_validators_from_state(state)
    endpoint_rows = _registry_validator_endpoints(request)
    now_ms = int(time.time() * 1000)
    max_age_ms = _validator_endpoint_max_age_ms()
    for ep in endpoint_rows:
        if isinstance(ep, dict):
            ep["freshness"] = _endpoint_freshness(ep, now_ms=now_ms, max_age_ms=max_age_ms)
    endpoints_by_account: dict[str, list[Json]] = {}
    endpoints_by_key: dict[str, list[Json]] = {}
    for ep in endpoint_rows:
        acct = str(ep.get("account_id") or "").strip()
        key = str(ep.get("node_pubkey") or "").strip()
        if acct:
            endpoints_by_account.setdefault(acct, []).append(ep)
        if key:
            endpoints_by_key.setdefault(key, []).append(ep)

    validators: list[Json] = []
    for account_id in active_validators:
        rec = _validator_record_from_state(state, account_id)
        node_pubkey = str(rec.get("node_pubkey") or rec.get("node_public_key") or "").strip()
        eps = list(endpoints_by_account.get(account_id, []))
        if node_pubkey:
            for ep in endpoints_by_key.get(node_pubkey, []):
                if ep not in eps:
                    eps.append(ep)
        verified_count = sum(1 for ep in eps if ep.get("verified") is True)
        verified_fresh_count = sum(
            1
            for ep in eps
            if ep.get("verified") is True and isinstance(ep.get("freshness"), dict) and ep["freshness"].get("fresh") is True
        )
        validators.append(
            {
                "account_id": account_id,
                "node_pubkey": node_pubkey,
                "active_in_protocol_state": True,
                "readiness_status": str(rec.get("readiness_status") or "").strip(),
                "endpoint_records": eps,
                "verified_endpoint_count": verified_count,
                "verified_fresh_endpoint_count": verified_fresh_count,
                "stale_verified_endpoint_count": max(0, verified_count - verified_fresh_count),
                "unverified_endpoint_count": sum(1 for ep in eps if ep.get("verified") is not True),
                "has_verified_fresh_endpoint": verified_fresh_count > 0,
            }
        )

    active_accounts = set(active_validators)
    hint_only = [
        ep
        for ep in endpoint_rows
        if str(ep.get("account_id") or "").strip() and str(ep.get("account_id") or "").strip() not in active_accounts
    ]

    commitments: Json = {}
    registry_status: Json = {"public_testnet": bool(_public_mode())}
    if _public_mode():
        registry = _load_public_registry_for_request(request)
        commitments = commitment_payload(registry)
        registry_status.update(
            {
                "active_validator_endpoint_policy": registry.get("active_validator_endpoint_policy", "verified_or_hint"),
                "seed_registry_signature_present": bool(str(registry.get("seed_registry_signature") or "").strip()),
                "seed_registry_signature_status": registry.get("seed_registry_signature_status", {}),
            }
        )

    return {
        "ok": True,
        "generated_ts_ms": int(time.time() * 1000),
        "public_testnet": bool(_public_mode()),
        "commitments": commitments,
        "active_validator_count": len(validators),
        "verified_endpoint_count": sum(int(v.get("verified_endpoint_count") or 0) for v in validators),
        "verified_fresh_endpoint_count": sum(int(v.get("verified_fresh_endpoint_count") or 0) for v in validators),
        "stale_verified_endpoint_count": sum(int(v.get("stale_verified_endpoint_count") or 0) for v in validators),
        "active_validators_missing_verified_fresh_endpoint_count": sum(1 for v in validators if not bool(v.get("has_verified_fresh_endpoint"))),
        "all_active_validators_have_verified_fresh_endpoint": all(bool(v.get("has_verified_fresh_endpoint")) for v in validators) if validators else True,
        "endpoint_freshness_policy": {"max_age_ms": max_age_ms},
        "validators": validators,
        "unverified_endpoint_hints": hint_only,
        "endpoint_authority_boundary": {
            "endpoint_advertisement_grants_validator_status": False,
            "validator_status_source": "protocol_state",
            "local_peer_hints_are_authoritative": False,
            "verified_endpoint_required_for_public_connection_target": bool(_public_mode()),
        },
        "registry": registry_status,
    }

@router.get("/v1/nodes")
def v1_nodes(request: Request) -> Json:
    """Removed legacy aggregate node directory endpoint.

    Direct protocol surfaces use /v1/nodes/seeds for configured bootstrap
    seeds and /v1/nodes/known for the node-local peer view.
    """
    raise ApiError.gone(
        "legacy_endpoint_removed",
        "/v1/nodes has been removed; use /v1/nodes/seeds or /v1/nodes/known",
        {"canonical_endpoints": ["/v1/nodes/seeds", "/v1/nodes/known"]},
    )


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


@router.get("/v1/nodes/validators")
def v1_nodes_validators(request: Request) -> Json:
    """Active protocol validators plus endpoint hints.

    Validator membership is read from protocol state only. Endpoint records are
    discoverability hints and never grant authority by themselves.
    """
    return _validator_endpoints_response(request)
