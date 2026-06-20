from __future__ import annotations

import json
import os
import time
from pathlib import Path
from typing import Any
from urllib.parse import urlparse, urlunparse

from weall.api.config import normalize_base_url

Json = dict[str, Any]

_TRUE = {"1", "true", "yes", "y", "on"}


class PublicSeedRegistryError(RuntimeError):
    """Raised when public-testnet seed discovery config is missing or unsafe."""


def env_truthy(name: str, default: bool = False) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return bool(default)
    return str(raw or "").strip().lower() in _TRUE


def public_testnet_enabled() -> bool:
    return env_truthy("WEALL_PUBLIC_TESTNET", False)


def public_testnet_allow_local() -> bool:
    if env_truthy("WEALL_PUBLIC_TESTNET_ALLOW_LOCAL", False):
        return True
    mode = str(os.environ.get("WEALL_MODE") or "").strip().lower()
    if mode in {"dev", "test", "local", "ci"}:
        return True
    return bool(os.environ.get("PYTEST_CURRENT_TEST"))


def public_seed_registry_path(default_path: str | None = None) -> str | None:
    raw = (
        os.environ.get("WEALL_PUBLIC_TESTNET_SEED_REGISTRY_PATH")
        or os.environ.get("WEALL_PUBLIC_SEED_REGISTRY_PATH")
        or default_path
        or ""
    )
    path = str(raw or "").strip()
    return path or None


def expected_public_commitments_from_env() -> Json:
    return {
        "network_id": str(os.environ.get("WEALL_PUBLIC_TESTNET_NETWORK_ID") or "").strip(),
        "chain_id": str(os.environ.get("WEALL_EXPECTED_CHAIN_ID") or os.environ.get("WEALL_CHAIN_ID") or "").strip(),
        "genesis_hash": str(os.environ.get("WEALL_EXPECTED_GENESIS_HASH") or os.environ.get("WEALL_GENESIS_HASH") or "").strip(),
        "protocol_profile_hash": str(os.environ.get("WEALL_EXPECTED_PROTOCOL_PROFILE_HASH") or "").strip(),
        "tx_index_hash": str(os.environ.get("WEALL_EXPECTED_TX_INDEX_HASH") or "").strip(),
    }


def _safe_str(value: Any) -> str:
    try:
        return str(value or "").strip()
    except Exception:
        return ""


def _require_str(data: Json, key: str) -> str:
    value = _safe_str(data.get(key))
    if not value:
        raise PublicSeedRegistryError(f"public_seed_registry_missing_{key}")
    return value


def _require_bool(data: Json, key: str, expected: bool) -> bool:
    value = data.get(key)
    if not isinstance(value, bool):
        raise PublicSeedRegistryError(f"public_seed_registry_missing_{key}")
    if value is not expected:
        raise PublicSeedRegistryError(f"public_seed_registry_bad_{key}")
    return value


def _list_of_strings(data: Json, key: str) -> list[str]:
    raw = data.get(key, [])
    if raw is None:
        return []
    if not isinstance(raw, list):
        raise PublicSeedRegistryError(f"public_seed_registry_bad_{key}")
    out: list[str] = []
    for item in raw:
        value = _safe_str(item)
        if value:
            out.append(value)
    return out


def _normalize_p2p_url(url: str) -> str:
    value = _safe_str(url)
    if not value:
        raise ValueError("p2p_url_empty")
    parsed = urlparse(value)
    scheme = (parsed.scheme or "").lower()
    if scheme not in {"tcp", "weall", "libp2p", "p2p"}:
        raise ValueError("p2p_url_bad_scheme")
    if not parsed.netloc:
        raise ValueError("p2p_url_missing_host")
    if parsed.query or parsed.fragment:
        raise ValueError("p2p_url_has_query_or_fragment")
    return urlunparse((scheme, parsed.netloc, parsed.path.rstrip("/"), "", "", "")).rstrip("/")


def _registry_nodes_from_seed_urls(seed_api_urls: list[str]) -> list[Json]:
    return [
        {
            "base_url": url,
            "role": "seed",
            "region": "",
            "weight": 100 - idx,
            "verified": True,
            "endpoint_source": "public_seed_registry",
        }
        for idx, url in enumerate(seed_api_urls)
    ]


def _normalize_validator_endpoint(raw: Any, *, allow_local: bool) -> Json | None:
    if not isinstance(raw, dict):
        raise PublicSeedRegistryError("public_validator_endpoint_not_object")
    account_id = _safe_str(raw.get("account_id") or raw.get("validator") or raw.get("account"))
    node_pubkey = _safe_str(raw.get("node_pubkey") or raw.get("node_public_key"))
    api_raw = _safe_str(raw.get("api_base_url") or raw.get("base_url") or raw.get("api_base") or raw.get("url"))
    p2p_raw = _safe_str(raw.get("p2p_url") or raw.get("peer_url") or raw.get("addr"))
    if not account_id and not node_pubkey:
        raise PublicSeedRegistryError("public_validator_endpoint_missing_identity")
    api_base_url = ""
    if api_raw:
        try:
            api_base_url = normalize_base_url(api_raw, allow_insecure_localhost_urls=allow_local)
        except Exception as exc:
            raise PublicSeedRegistryError("public_validator_endpoint_invalid_api_base_url") from exc
    p2p_url = ""
    if p2p_raw:
        p2p_url = _normalize_p2p_url(p2p_raw)
    if not api_base_url and not p2p_url:
        raise PublicSeedRegistryError("public_validator_endpoint_missing_url")
    verified = bool(raw.get("verified") is True or raw.get("signed") is True or _safe_str(raw.get("signature")))
    return {
        "account_id": account_id,
        "node_pubkey": node_pubkey,
        "api_base_url": api_base_url,
        "p2p_url": p2p_url,
        "endpoint_source": _safe_str(raw.get("endpoint_source") or raw.get("source") or "public_seed_registry"),
        "last_seen_ms": int(raw.get("last_seen_ms") or raw.get("proof_timestamp_ms") or 0),
        "proof_timestamp_ms": int(raw.get("proof_timestamp_ms") or raw.get("last_seen_ms") or 0),
        "verified": bool(verified),
        "signed": bool(raw.get("signed") is True or _safe_str(raw.get("signature"))),
        "signature": _safe_str(raw.get("signature")),
        "signer": _safe_str(raw.get("signer") or raw.get("seed_registry_signer")),
    }


def _normalize_nodes(raw_nodes: Any, *, allow_local: bool) -> list[Json]:
    if raw_nodes is None:
        return []
    if not isinstance(raw_nodes, list):
        raise PublicSeedRegistryError("public_seed_registry_bad_nodes")
    out: list[Json] = []
    for raw in raw_nodes:
        if not isinstance(raw, dict):
            raise PublicSeedRegistryError("public_seed_registry_node_not_object")
        base_raw = _safe_str(raw.get("base_url") or raw.get("api_base_url") or raw.get("api_base") or raw.get("url"))
        if not base_raw:
            raise PublicSeedRegistryError("public_seed_registry_node_missing_base_url")
        try:
            base_url = normalize_base_url(base_raw, allow_insecure_localhost_urls=allow_local)
        except Exception as exc:
            raise PublicSeedRegistryError("public_seed_registry_node_invalid_base_url") from exc
        out.append(
            {
                "base_url": base_url,
                "role": _safe_str(raw.get("role") or "seed") or "seed",
                "region": _safe_str(raw.get("region")),
                "weight": int(raw.get("weight") or 0),
                "verified": bool(raw.get("verified") is True or _safe_str(raw.get("signature"))),
                "endpoint_source": _safe_str(raw.get("endpoint_source") or raw.get("source") or "public_seed_registry"),
            }
        )
    return out


def normalize_public_seed_registry(data: Json, *, allow_local: bool) -> Json:
    if not isinstance(data, dict):
        raise PublicSeedRegistryError("public_seed_registry_not_object")

    network_id = _require_str(data, "network_id")
    chain_id = _require_str(data, "chain_id")
    genesis_hash = _require_str(data, "genesis_hash")
    protocol_profile_hash = _require_str(data, "protocol_profile_hash")
    tx_index_hash = _require_str(data, "tx_index_hash")
    resettable_testnet = _require_bool(data, "resettable_testnet", True)
    economics_active = _require_bool(data, "economics_active", False)

    seed_api_urls: list[str] = []
    seen_api: set[str] = set()
    for raw in _list_of_strings(data, "seed_api_urls"):
        try:
            norm = normalize_base_url(raw, allow_insecure_localhost_urls=allow_local)
        except Exception as exc:
            raise PublicSeedRegistryError("public_seed_registry_invalid_seed_api_url") from exc
        if norm not in seen_api:
            seen_api.add(norm)
            seed_api_urls.append(norm)

    seed_p2p_urls: list[str] = []
    seen_p2p: set[str] = set()
    for raw in _list_of_strings(data, "seed_p2p_urls"):
        norm = _normalize_p2p_url(raw)
        if norm not in seen_p2p:
            seen_p2p.add(norm)
            seed_p2p_urls.append(norm)

    nodes = _normalize_nodes(data.get("nodes"), allow_local=allow_local)
    if not seed_api_urls:
        for node in nodes:
            base_url = _safe_str(node.get("base_url"))
            if base_url and base_url not in seen_api:
                seen_api.add(base_url)
                seed_api_urls.append(base_url)
    if not nodes:
        nodes = _registry_nodes_from_seed_urls(seed_api_urls)
    if not seed_api_urls:
        raise PublicSeedRegistryError("public_seed_registry_no_seed_api_urls")

    endpoints_raw = data.get("validator_endpoints") or []
    if not isinstance(endpoints_raw, list):
        raise PublicSeedRegistryError("public_seed_registry_bad_validator_endpoints")
    validator_endpoints = [
        item
        for item in (_normalize_validator_endpoint(raw, allow_local=allow_local) for raw in endpoints_raw)
        if isinstance(item, dict)
    ]

    policy = _safe_str(data.get("active_validator_endpoint_policy") or "verified_or_hint") or "verified_or_hint"
    if policy not in {"verified_only", "verified_or_hint", "hints_only"}:
        raise PublicSeedRegistryError("public_seed_registry_bad_active_validator_endpoint_policy")

    return {
        "version": int(data.get("version") or 1),
        "network_id": network_id,
        "chain_id": chain_id,
        "genesis_hash": genesis_hash,
        "protocol_profile_hash": protocol_profile_hash,
        "tx_index_hash": tx_index_hash,
        "seed_api_urls": seed_api_urls,
        "seed_p2p_urls": seed_p2p_urls,
        "seed_registry_signature": _safe_str(data.get("seed_registry_signature")),
        "seed_registry_signer": _safe_str(data.get("seed_registry_signer")),
        "active_validator_endpoint_policy": policy,
        "resettable_testnet": resettable_testnet,
        "economics_active": economics_active,
        "nodes": nodes,
        "validator_endpoints": validator_endpoints,
        "generated_ts_ms": int(data.get("generated_ts_ms") or time.time() * 1000),
    }


def load_public_seed_registry(path: str | None = None, *, allow_local: bool | None = None) -> Json:
    resolved = public_seed_registry_path(path)
    if not resolved:
        raise PublicSeedRegistryError("public_seed_registry_path_missing")
    p = Path(resolved).expanduser()
    if not p.exists():
        raise PublicSeedRegistryError("public_seed_registry_missing")
    if not p.is_file():
        raise PublicSeedRegistryError("public_seed_registry_not_file")
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise PublicSeedRegistryError("public_seed_registry_bad_json") from exc
    try:
        return normalize_public_seed_registry(data, allow_local=public_testnet_allow_local() if allow_local is None else bool(allow_local))
    except PublicSeedRegistryError:
        raise
    except Exception as exc:
        raise PublicSeedRegistryError(str(exc) or "public_seed_registry_invalid") from exc


def commitment_payload(registry: Json) -> Json:
    return {
        "network_id": _safe_str(registry.get("network_id")),
        "chain_id": _safe_str(registry.get("chain_id")),
        "genesis_hash": _safe_str(registry.get("genesis_hash")),
        "protocol_profile_hash": _safe_str(registry.get("protocol_profile_hash")),
        "tx_index_hash": _safe_str(registry.get("tx_index_hash")),
        "resettable_testnet": bool(registry.get("resettable_testnet") is True),
        "economics_active": bool(registry.get("economics_active") is True),
    }


def verified_tx_upstreams_from_registry(registry: Json) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    for endpoint in registry.get("validator_endpoints") or []:
        if not isinstance(endpoint, dict):
            continue
        if endpoint.get("verified") is not True:
            continue
        url = _safe_str(endpoint.get("api_base_url"))
        if not url or url in seen:
            continue
        seen.add(url)
        out.append(url)
    for url in registry.get("seed_api_urls") or []:
        value = _safe_str(url)
        if value and value not in seen:
            seen.add(value)
            out.append(value)
    return out
