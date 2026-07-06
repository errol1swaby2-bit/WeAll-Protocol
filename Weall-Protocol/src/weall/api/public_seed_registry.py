from __future__ import annotations

import ipaddress
import json
import os
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any
from urllib.parse import urlparse, urlunparse

from weall.api.config import normalize_base_url
from weall.crypto.sig import verify_signature_for_profile
from weall.crypto.signature_profiles import (
    LEGACY_ED25519_V1,
    PQ_MLDSA_V1,
    mode_requires_explicit_sig_profile,
    normalize_signature_profile_id,
    profile_allowed_for_context,
)

Json = dict[str, Any]

_TRUE = {"1", "true", "yes", "y", "on"}

_REGISTRY_SIGNATURE_OMIT = {
    "seed_registry_signature",
    "seed_registry_signature_alg",
    "seed_registry_sig_profile",
    "sig_profile",
    "signature",
}
_ENDPOINT_SIGNATURE_OMIT = {"signature", "signed", "verified", "sig_profile", "signature_profile"}


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


def public_seed_trust_roots_path(default_path: str | None = None) -> str | None:
    raw = (
        os.environ.get("WEALL_PUBLIC_TESTNET_TRUST_ROOTS_PATH")
        or os.environ.get("WEALL_PUBLIC_TRUST_ROOTS_PATH")
        or default_path
        or ""
    )
    path = str(raw or "").strip()
    return path or None


def public_seed_trust_roots_default_path() -> str | None:
    mode = str(os.environ.get("WEALL_MODE") or "prod").strip().lower()
    if mode != "prod" and not env_truthy("WEALL_PUBLIC_TESTNET_USE_DEFAULT_TRUST_ROOTS", False):
        return None
    candidates = [
        os.environ.get("WEALL_PUBLIC_TESTNET_DEFAULT_TRUST_ROOTS_PATH"),
        str(Path.cwd() / "public_testnet_trust_roots.json"),
        str(Path.cwd() / "config" / "public_testnet_trust_roots.json"),
        str(Path.cwd() / "configs" / "public_testnet_trust_roots.json"),
        str(Path.cwd() / "Weall-Protocol" / "config" / "public_testnet_trust_roots.json"),
        str(Path.cwd() / "Weall-Protocol" / "configs" / "public_testnet_trust_roots.json"),
    ]
    for raw in candidates:
        value = _safe_str(raw)
        if not value:
            continue
        try:
            if Path(value).expanduser().is_file():
                return value
        except Exception:
            continue
    return None


def load_public_seed_trust_roots(path: str | None = None) -> Json:
    resolved = public_seed_trust_roots_path(path) or public_seed_trust_roots_default_path()
    if not resolved:
        return {}
    p = Path(resolved).expanduser()
    if not p.exists():
        if public_seed_trust_roots_path(path):
            raise PublicSeedRegistryError("public_seed_trust_roots_missing")
        return {}
    if not p.is_file():
        raise PublicSeedRegistryError("public_seed_trust_roots_not_file")
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise PublicSeedRegistryError("public_seed_trust_roots_bad_json") from exc
    if not isinstance(data, dict):
        raise PublicSeedRegistryError("public_seed_trust_roots_not_object")
    return dict(data)


def _trust_root_list(*keys: str) -> list[str]:
    try:
        roots = load_public_seed_trust_roots()
    except PublicSeedRegistryError:
        raise
    except Exception as exc:
        raise PublicSeedRegistryError("public_seed_trust_roots_read_failed") from exc
    out: list[str] = []
    for key in keys:
        raw = roots.get(key)
        if isinstance(raw, list):
            out.extend(_safe_str(item) for item in raw if _safe_str(item))
        else:
            value = _safe_str(raw)
            if value:
                out.append(value)
    return out


def _trust_root_registry_mirror_urls() -> list[str]:
    """Return provider-neutral signed-registry mirror URL candidates.

    Trust-root mirrors are publication locations only. A host/provider name is
    never authority; every candidate must still pass registry signature, signer
    pin, and pinned chain-commitment checks before it is accepted.
    """

    try:
        roots = load_public_seed_trust_roots()
    except PublicSeedRegistryError:
        raise
    except Exception as exc:
        raise PublicSeedRegistryError("public_seed_trust_roots_read_failed") from exc

    out: list[str] = []
    mirrors = roots.get("seed_registry_mirrors")
    if isinstance(mirrors, list):
        for item in mirrors:
            if isinstance(item, dict):
                value = _safe_str(item.get("url") or item.get("href"))
            else:
                value = _safe_str(item)
            if value:
                out.append(value)
    elif mirrors is not None:
        value = _safe_str(mirrors)
        if value:
            out.append(value)

    # Backward-compatible legacy keys. They remain generic URL candidates, not
    # named-provider dependencies.
    out.extend(_trust_root_list("seed_registry_urls", "seed_registry_url", "registry_urls", "registry_url"))
    return out


def public_seed_registry_urls(default_url: str | None = None) -> list[str]:
    """Return configured signed public seed-registry URL candidates.

    Discovery is provider-neutral: remote URLs are optional mirrors that publish
    bytes. The checked-in signed registry remains the baseline fallback, and all
    remote bytes are accepted only after the same signature, signer-pin, and
    chain-commitment checks as local files.
    """

    raw_values = [
        os.environ.get("WEALL_PUBLIC_TESTNET_SEED_REGISTRY_URLS"),
        os.environ.get("WEALL_PUBLIC_TESTNET_SEED_REGISTRY_URL"),
        os.environ.get("WEALL_PUBLIC_SEED_REGISTRY_URLS"),
        os.environ.get("WEALL_PUBLIC_SEED_REGISTRY_URL"),
        *_trust_root_registry_mirror_urls(),
        default_url,
    ]
    out: list[str] = []
    seen: set[str] = set()
    for raw in raw_values:
        for part in str(raw or "").replace("\n", ",").split(","):
            url = _safe_str(part)
            if not url or url in seen:
                continue
            seen.add(url)
            out.append(url)
    return out


def _normalize_registry_url(url: str, *, allow_local: bool) -> str:
    value = _safe_str(url)
    if not value:
        raise PublicSeedRegistryError("public_seed_registry_remote_url_empty")
    parsed = urlparse(value)
    if parsed.query or parsed.fragment:
        raise PublicSeedRegistryError("public_seed_registry_remote_url_query_or_fragment")
    scheme = (parsed.scheme or "").lower()
    host = (parsed.hostname or "").lower()
    if not host:
        raise PublicSeedRegistryError("public_seed_registry_remote_url_missing_host")
    if scheme == "https":
        pass
    elif scheme == "http" and allow_local and host in {"localhost", "127.0.0.1"}:
        pass
    else:
        raise PublicSeedRegistryError("public_seed_registry_remote_url_must_be_https")
    path = parsed.path or "/"
    return urlunparse((scheme, parsed.netloc, path, "", "", ""))


def _remote_registry_timeout_s() -> float:
    raw = os.environ.get("WEALL_PUBLIC_TESTNET_SEED_REGISTRY_TIMEOUT_S") or "3.0"
    try:
        return max(0.25, float(str(raw).strip() or "3.0"))
    except Exception:
        return 3.0


def _http_get_registry_json(url: str, *, timeout_s: float) -> Json:
    try:
        req = urllib.request.Request(
            url,
            headers={
                "Accept": "application/json",
                "User-Agent": "weall-public-seed-registry/1.0",
            },
        )
        with urllib.request.urlopen(req, timeout=float(timeout_s)) as resp:
            raw = resp.read()
    except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError) as exc:
        raise PublicSeedRegistryError("public_seed_registry_remote_fetch_failed") from exc
    except Exception as exc:
        raise PublicSeedRegistryError("public_seed_registry_remote_fetch_failed") from exc
    try:
        data = json.loads(raw.decode("utf-8"))
    except Exception as exc:
        raise PublicSeedRegistryError("public_seed_registry_remote_bad_json") from exc
    if not isinstance(data, dict):
        raise PublicSeedRegistryError("public_seed_registry_remote_not_object")
    return data


def public_seed_registry_default_path() -> str | None:
    """Return the bundled public testnet registry path when present.

    Operators may still override with ``WEALL_PUBLIC_TESTNET_SEED_REGISTRY_PATH``.
    The bundled path is intentionally explicit and version-controlled so an
    open-download observer can boot without being handed a private bundle.
    """

    candidates = [
        os.environ.get("WEALL_PUBLIC_TESTNET_DEFAULT_SEED_REGISTRY_PATH"),
        str(Path.cwd() / "public_testnet_seed_registry.json"),
        str(Path.cwd() / "config" / "public_testnet_seed_registry.json"),
        str(Path.cwd() / "configs" / "public_testnet_seed_registry.json"),
        str(Path.cwd() / "Weall-Protocol" / "config" / "public_testnet_seed_registry.json"),
        str(Path.cwd() / "Weall-Protocol" / "configs" / "public_testnet_seed_registry.json"),
    ]
    for raw in candidates:
        value = _safe_str(raw)
        if not value:
            continue
        try:
            if Path(value).expanduser().is_file():
                return value
        except Exception:
            continue
    return None


def expected_public_commitments_from_env() -> Json:
    return {
        "network_id": str(os.environ.get("WEALL_PUBLIC_TESTNET_NETWORK_ID") or "").strip(),
        "chain_id": str(os.environ.get("WEALL_EXPECTED_CHAIN_ID") or os.environ.get("WEALL_CHAIN_ID") or "").strip(),
        "genesis_hash": str(os.environ.get("WEALL_EXPECTED_GENESIS_HASH") or os.environ.get("WEALL_GENESIS_HASH") or "").strip(),
        "protocol_profile_hash": str(os.environ.get("WEALL_EXPECTED_PROTOCOL_PROFILE_HASH") or "").strip(),
        "tx_index_hash": str(os.environ.get("WEALL_EXPECTED_TX_INDEX_HASH") or "").strip(),
    }



_PLACEHOLDER_MARKERS = (
    "<",
    "set-before-public-launch",
    "required-prod",
    "required-ed25519",
    "testnet.weall.example",
    "@validator-account-id",
    "validator-node-public-key",
)




def public_seed_trust_root_commitments() -> Json:
    try:
        roots = load_public_seed_trust_roots()
    except PublicSeedRegistryError:
        raise
    except Exception as exc:
        raise PublicSeedRegistryError("public_seed_trust_roots_read_failed") from exc
    out: Json = {}
    for key in ("network_id", "chain_id", "genesis_hash", "protocol_profile_hash", "tx_index_hash"):
        value = _safe_str(roots.get(key) or roots.get(f"expected_{key}"))
        if value:
            out[key] = value
    return out


def expected_public_commitments() -> Json:
    out = public_seed_trust_root_commitments()
    env = expected_public_commitments_from_env()
    for key, value in env.items():
        text = _safe_str(value)
        if text:
            out[key] = text
    return out


def _enforce_expected_public_commitments(commitments: Json) -> None:
    expected = expected_public_commitments()
    for key in ("network_id", "chain_id", "genesis_hash", "protocol_profile_hash", "tx_index_hash"):
        wanted = _safe_str(expected.get(key))
        if not wanted:
            continue
        actual = _safe_str(commitments.get(key))
        if actual != wanted:
            raise PublicSeedRegistryError(f"public_seed_registry_{key}_mismatch")


def _placeholderish(value: Any) -> bool:
    text = _safe_str(value).lower()
    if not text:
        return False
    return any(marker in text for marker in _PLACEHOLDER_MARKERS)


def _reject_placeholder_value(path: str, value: Any) -> None:
    if _placeholderish(value):
        raise PublicSeedRegistryError(f"public_seed_registry_placeholder_{path}")


def _reject_public_launch_placeholders(data: Json) -> None:
    """Reject template/demo values before a public observer can trust them.

    This is intentionally stricter than generic schema validation.  The file
    under configs/*.example.json is documentation, not a launch registry.  A
    production public observer must not accidentally boot from placeholder
    commitments, .example hostnames, or unsigned token strings.
    """

    for key in (
        "network_id",
        "chain_id",
        "genesis_hash",
        "protocol_profile_hash",
        "tx_index_hash",
        "seed_registry_signer",
        "seed_registry_signature",
    ):
        _reject_placeholder_value(key, data.get(key))
    for idx, url in enumerate(_list_of_strings(data, "seed_api_urls")):
        _reject_placeholder_value(f"seed_api_urls_{idx}", url)
    for idx, url in enumerate(_list_of_strings(data, "seed_p2p_urls")):
        _reject_placeholder_value(f"seed_p2p_urls_{idx}", url)
    nodes = data.get("nodes") or []
    if isinstance(nodes, list):
        for idx, node in enumerate(nodes):
            if isinstance(node, dict):
                _reject_placeholder_value(f"nodes_{idx}_base_url", node.get("base_url") or node.get("api_base_url") or node.get("url"))
    endpoints = data.get("validator_endpoints") or []
    if isinstance(endpoints, list):
        for idx, endpoint in enumerate(endpoints):
            if not isinstance(endpoint, dict):
                continue
            for key in ("account_id", "node_pubkey", "node_public_key", "api_base_url", "base_url", "p2p_url", "signature", "signer"):
                if key in endpoint:
                    _reject_placeholder_value(f"validator_endpoints_{idx}_{key}", endpoint.get(key))

def _env_list(name: str) -> list[str]:
    raw = str(os.environ.get(name) or "").strip()
    if not raw:
        return []
    return [part.strip() for part in raw.replace("\n", ",").split(",") if part.strip()]


def _signature_required() -> bool:
    """Return whether public registry signatures are mandatory.

    Production public-testnet mode defaults to signed registries.  Tests and
    local rehearsals may explicitly opt out with
    WEALL_PUBLIC_TESTNET_REQUIRE_SIGNATURES=0 when exercising malformed schema
    failures before the signature gate.
    """

    raw = os.environ.get("WEALL_PUBLIC_TESTNET_REQUIRE_SIGNATURES")
    if raw is not None:
        return str(raw).strip().lower() in _TRUE
    mode = str(os.environ.get("WEALL_MODE") or "prod").strip().lower()
    return public_testnet_enabled() and mode == "prod"


def _registry_signer_pins() -> set[str]:
    pins = set(_env_list("WEALL_PUBLIC_TESTNET_SEED_REGISTRY_PUBKEYS"))
    pins.update(_env_list("WEALL_PUBLIC_TESTNET_SEED_REGISTRY_PUBKEY"))
    pins.update(
        _trust_root_list(
            "seed_registry_pubkeys",
            "seed_registry_pubkey",
            "registry_signer_pubkeys",
            "registry_signer_pubkey",
        )
    )
    return {_safe_str(pin) for pin in pins if _safe_str(pin)}

def _trust_root_allowed_signature_profiles() -> list[str]:
    try:
        roots = load_public_seed_trust_roots()
    except PublicSeedRegistryError:
        raise
    except Exception as exc:
        raise PublicSeedRegistryError("public_seed_trust_roots_read_failed") from exc
    raw = roots.get("allowed_signature_profiles") or roots.get("seed_registry_allowed_signature_profiles")
    if isinstance(raw, list):
        return [normalize_signature_profile_id(item) for item in raw if normalize_signature_profile_id(item)]
    value = normalize_signature_profile_id(raw)
    return [value] if value else []


def _allow_legacy_seed_registry_signatures() -> bool:
    if env_truthy("WEALL_PUBLIC_TESTNET_ALLOW_LEGACY_SIGNATURES", False):
        return True
    mode = str(os.environ.get("WEALL_MODE") or "prod").strip().lower()
    return mode in {"dev", "test", "local", "ci"}


def _seed_registry_profile_allowed(profile: str) -> bool:
    if profile == LEGACY_ED25519_V1 and _allow_legacy_seed_registry_signatures():
        return True
    allowed = _trust_root_allowed_signature_profiles()
    if allowed:
        return profile in allowed
    if mode_requires_explicit_sig_profile():
        return profile == PQ_MLDSA_V1
    return profile in {LEGACY_ED25519_V1, PQ_MLDSA_V1}



def _pinned_registry_signer_required() -> bool:
    raw = os.environ.get("WEALL_PUBLIC_TESTNET_REQUIRE_PINNED_REGISTRY_SIGNER")
    if raw is not None:
        return str(raw).strip().lower() in _TRUE
    mode = str(os.environ.get("WEALL_MODE") or "prod").strip().lower()
    return public_testnet_enabled() and mode == "prod"


def _canonical_json_bytes(data: Any) -> bytes:
    return json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _without_keys(value: Any, omit: set[str]) -> Any:
    if isinstance(value, dict):
        return {str(k): _without_keys(v, omit) for k, v in value.items() if str(k) not in omit}
    if isinstance(value, list):
        return [_without_keys(item, omit) for item in value]
    return value


def registry_signature_payload(data: Json) -> bytes:
    """Canonical, domain-separated public seed registry signature payload."""

    return _canonical_json_bytes(
        {
            "domain": "weall.public_seed_registry.v1",
            "registry": _without_keys(data, _REGISTRY_SIGNATURE_OMIT),
        }
    )


def validator_endpoint_signature_payload(raw: Json, *, commitments: Json) -> bytes:
    """Canonical, domain-separated validator endpoint-advertisement payload."""

    return _canonical_json_bytes(
        {
            "domain": "weall.public_validator_endpoint.v1",
            "commitments": {
                "network_id": _safe_str(commitments.get("network_id")),
                "chain_id": _safe_str(commitments.get("chain_id")),
                "genesis_hash": _safe_str(commitments.get("genesis_hash")),
                "protocol_profile_hash": _safe_str(commitments.get("protocol_profile_hash")),
                "tx_index_hash": _safe_str(commitments.get("tx_index_hash")),
            },
            "endpoint": _without_keys(raw, _ENDPOINT_SIGNATURE_OMIT),
        }
    )


def _verify_registry_signature(data: Json) -> Json:
    signer = _safe_str(data.get("seed_registry_signer"))
    sig = _safe_str(data.get("seed_registry_signature"))
    profile = normalize_signature_profile_id(
        data.get("seed_registry_sig_profile")
        or data.get("sig_profile")
        or data.get("seed_registry_signature_profile")
    )
    if not profile:
        if mode_requires_explicit_sig_profile():
            profile = PQ_MLDSA_V1
        else:
            profile = LEGACY_ED25519_V1

    if not _seed_registry_profile_allowed(profile):
        raise PublicSeedRegistryError("public_seed_registry_signature_profile_not_allowed")
    profile_chain_config = None
    if profile == LEGACY_ED25519_V1 and _allow_legacy_seed_registry_signatures():
        profile_chain_config = {"crypto": {"allowed_signature_profiles": [LEGACY_ED25519_V1], "allow_legacy_ed25519": True}}
    ok_profile, reason = profile_allowed_for_context(profile, chain_config=profile_chain_config, require_verifier=True)
    if not ok_profile:
        raise PublicSeedRegistryError(f"public_seed_registry_{reason}")

    if not signer or not sig:
        if _signature_required():
            missing = "seed_registry_signer" if not signer else "seed_registry_signature"
            raise PublicSeedRegistryError(f"public_seed_registry_missing_{missing}")
        return {"required": False, "verified": False, "signer": signer, "sig_profile": profile, "trust": "unsigned_local_rehearsal"}

    ok = verify_signature_for_profile(
        sig_profile=profile,
        message=registry_signature_payload(data),
        sig=sig,
        pubkey=signer,
    )
    if not ok:
        raise PublicSeedRegistryError("public_seed_registry_bad_signature")
    pins = _registry_signer_pins()
    if pins and signer not in pins:
        raise PublicSeedRegistryError("public_seed_registry_unpinned_signer")
    if _pinned_registry_signer_required() and not pins:
        raise PublicSeedRegistryError("public_seed_registry_signer_pin_missing")
    return {
        "required": bool(_signature_required()),
        "verified": True,
        "signer": signer,
        "sig_profile": profile,
        "trust": "pinned" if pins else "self_declared_local_rehearsal",
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


def _endpoint_host_kind(host: str) -> str:
    value = _safe_str(host).strip("[]").lower()
    if not value:
        return "missing"
    if value in {"localhost", "localhost.localdomain"}:
        return "loopback"
    if value in {"0.0.0.0", "::", "*"}:
        return "unspecified"
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        return "dns"
    if ip.is_loopback:
        return "loopback"
    if ip.is_unspecified:
        return "unspecified"
    if ip.is_private:
        return "private"
    if ip.is_link_local:
        return "link_local"
    if ip.is_reserved:
        return "reserved"
    if ip.is_multicast:
        return "multicast"
    return "public_ip"


def _require_public_endpoint_host(value: str, *, error_code: str, allow_local: bool) -> None:
    if allow_local:
        return
    parsed = urlparse(_safe_str(value))
    kind = _endpoint_host_kind(parsed.hostname or "")
    if kind in {"dns", "public_ip"}:
        return
    raise PublicSeedRegistryError(error_code)


def _normalize_p2p_url(url: str) -> str:
    value = _safe_str(url)
    if not value:
        raise ValueError("p2p_url_empty")
    parsed = urlparse(value)
    scheme = (parsed.scheme or "").lower()
    if scheme not in {"tcp", "tls"}:
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


def _verify_validator_endpoint_signature(raw: Json, *, commitments: Json) -> Json:
    signer = _safe_str(raw.get("signer") or raw.get("node_pubkey") or raw.get("node_public_key"))
    sig = _safe_str(raw.get("signature"))
    profile = normalize_signature_profile_id(raw.get("sig_profile") or raw.get("signature_profile"))
    if not profile:
        if mode_requires_explicit_sig_profile():
            profile = PQ_MLDSA_V1
        else:
            profile = LEGACY_ED25519_V1
    requested_verified = bool(raw.get("verified") is True or raw.get("signed") is True or sig)
    if not _seed_registry_profile_allowed(profile):
        return {"verified": False, "signed": False, "error": "validator_endpoint_signature_profile_not_allowed", "signer": signer, "sig_profile": profile}
    if not signer or not sig:
        if requested_verified or _signature_required():
            return {"verified": False, "signed": False, "error": "validator_endpoint_signature_missing", "signer": signer, "sig_profile": profile}
        return {"verified": False, "signed": False, "error": "validator_endpoint_unsigned_hint", "signer": signer, "sig_profile": profile}
    ok = verify_signature_for_profile(
        sig_profile=profile,
        message=validator_endpoint_signature_payload(raw, commitments=commitments),
        sig=sig,
        pubkey=signer,
    )
    return {
        "verified": bool(ok),
        "signed": bool(ok),
        "error": "" if ok else "validator_endpoint_bad_signature",
        "signer": signer,
        "sig_profile": profile,
    }

def _normalize_validator_endpoint(raw: Any, *, allow_local: bool, commitments: Json) -> Json | None:
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
    if public_testnet_enabled() and _signature_required():
        if api_base_url:
            _require_public_endpoint_host(
                api_base_url,
                error_code="public_validator_endpoint_api_base_url_not_public",
                allow_local=allow_local,
            )
        if p2p_url:
            _require_public_endpoint_host(
                p2p_url,
                error_code="public_validator_endpoint_p2p_url_not_public",
                allow_local=allow_local,
            )
    if not api_base_url and not p2p_url:
        raise PublicSeedRegistryError("public_validator_endpoint_missing_url")
    verification = _verify_validator_endpoint_signature(raw, commitments=commitments)
    if _signature_required() and not bool(verification.get("verified")):
        raise PublicSeedRegistryError(str(verification.get("error") or "public_validator_endpoint_bad_signature"))
    return {
        "account_id": account_id,
        "node_pubkey": node_pubkey,
        "api_base_url": api_base_url,
        "p2p_url": p2p_url,
        "endpoint_source": _safe_str(raw.get("endpoint_source") or raw.get("source") or "public_seed_registry"),
        "last_seen_ms": int(raw.get("last_seen_ms") or raw.get("proof_timestamp_ms") or 0),
        "proof_timestamp_ms": int(raw.get("proof_timestamp_ms") or raw.get("last_seen_ms") or 0),
        "verified": bool(verification.get("verified")),
        "signed": bool(verification.get("signed")),
        "signature": _safe_str(raw.get("signature")),
        "sig_profile": _safe_str(verification.get("sig_profile") or raw.get("sig_profile") or raw.get("signature_profile")),
        "signer": _safe_str(verification.get("signer") or raw.get("signer") or raw.get("seed_registry_signer")),
        "signature_error": _safe_str(verification.get("error")),
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
    if public_testnet_enabled() and _signature_required():
        _reject_public_launch_placeholders(data)

    network_id = _require_str(data, "network_id")
    chain_id = _require_str(data, "chain_id")
    genesis_hash = _require_str(data, "genesis_hash")
    protocol_profile_hash = _require_str(data, "protocol_profile_hash")
    tx_index_hash = _require_str(data, "tx_index_hash")
    resettable_testnet = _require_bool(data, "resettable_testnet", True)
    economics_active = _require_bool(data, "economics_active", False)
    signature_status = _verify_registry_signature(data)
    commitments = {
        "network_id": network_id,
        "chain_id": chain_id,
        "genesis_hash": genesis_hash,
        "protocol_profile_hash": protocol_profile_hash,
        "tx_index_hash": tx_index_hash,
    }

    seed_api_urls: list[str] = []
    seen_api: set[str] = set()
    for raw in _list_of_strings(data, "seed_api_urls"):
        try:
            norm = normalize_base_url(raw, allow_insecure_localhost_urls=allow_local)
        except Exception as exc:
            raise PublicSeedRegistryError("public_seed_registry_invalid_seed_api_url") from exc
        if public_testnet_enabled() and _signature_required():
            _require_public_endpoint_host(
                norm,
                error_code="public_seed_registry_seed_api_url_not_public",
                allow_local=allow_local,
            )
        if norm not in seen_api:
            seen_api.add(norm)
            seed_api_urls.append(norm)

    seed_p2p_urls: list[str] = []
    seen_p2p: set[str] = set()
    for raw in _list_of_strings(data, "seed_p2p_urls"):
        norm = _normalize_p2p_url(raw)
        if public_testnet_enabled() and _signature_required():
            _require_public_endpoint_host(
                norm,
                error_code="public_seed_registry_seed_p2p_url_not_public",
                allow_local=allow_local,
            )
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
    if public_testnet_enabled() and _signature_required() and not seed_p2p_urls:
        raise PublicSeedRegistryError("public_seed_registry_no_seed_p2p_urls")

    endpoints_raw = data.get("validator_endpoints") or []
    if not isinstance(endpoints_raw, list):
        raise PublicSeedRegistryError("public_seed_registry_bad_validator_endpoints")
    validator_endpoints = [
        item
        for item in (
            _normalize_validator_endpoint(raw, allow_local=allow_local, commitments=commitments)
            for raw in endpoints_raw
        )
        if isinstance(item, dict)
    ]

    policy = _safe_str(data.get("active_validator_endpoint_policy") or "verified_or_hint") or "verified_or_hint"
    if policy not in {"verified_only", "verified_or_hint", "hints_only"}:
        raise PublicSeedRegistryError("public_seed_registry_bad_active_validator_endpoint_policy")

    _enforce_expected_public_commitments(commitments)

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
        "seed_registry_sig_profile": _safe_str(data.get("seed_registry_sig_profile") or data.get("sig_profile") or data.get("seed_registry_signature_profile")),
        "seed_registry_signer": _safe_str(data.get("seed_registry_signer")),
        "seed_registry_signature_status": signature_status,
        "active_validator_endpoint_policy": policy,
        "resettable_testnet": resettable_testnet,
        "economics_active": economics_active,
        "nodes": nodes,
        "validator_endpoints": validator_endpoints,
        "generated_ts_ms": int(data.get("generated_ts_ms") or time.time() * 1000),
    }


def _load_public_seed_registry_file(resolved: str, *, allow_local: bool) -> Json:
    p = Path(resolved).expanduser()
    if not p.exists():
        raise PublicSeedRegistryError("public_seed_registry_missing")
    if not p.is_file():
        raise PublicSeedRegistryError("public_seed_registry_not_file")
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise PublicSeedRegistryError("public_seed_registry_bad_json") from exc
    out = normalize_public_seed_registry(data, allow_local=allow_local)
    out["registry_source_kind"] = "file"
    out["registry_source"] = str(p)
    out["registry_source_provider"] = "local_file"
    out["provider_authority"] = False
    out["registry_mirror_attempts"] = [
        {
            "source_kind": "file",
            "provider": "local_file",
            "url": str(p),
            "accepted": True,
            "failure_code": "",
        }
    ]
    return out


def _load_public_seed_registry_remote(url: str, *, allow_local: bool) -> Json:
    normalized = _normalize_registry_url(url, allow_local=allow_local)
    data = _http_get_registry_json(normalized, timeout_s=_remote_registry_timeout_s())
    out = normalize_public_seed_registry(data, allow_local=allow_local)
    out["registry_source_kind"] = "remote_url"
    out["registry_source"] = normalized
    out["registry_source_provider"] = "generic_https" if urlparse(normalized).scheme == "https" else "local_http_rehearsal"
    out["provider_authority"] = False
    out["registry_mirror_attempts"] = [
        {
            "source_kind": "remote_url",
            "provider": out["registry_source_provider"],
            "url": normalized,
            "accepted": True,
            "failure_code": "",
        }
    ]
    return out


def load_public_seed_registry(
    path: str | None = None,
    *,
    allow_local: bool | None = None,
    url: str | None = None,
) -> Json:
    """Load the signed public seed registry from provider-neutral sources.

    Source order is intentionally fail-closed for explicit operator choices:

    * An explicit path (argument or env) is authoritative and must load.
    * Otherwise, optional generic remote signed-registry mirrors are tried.
      Hosts publish bytes only; signature + signer-pin + chain commitment checks
      create trust.
    * If all remotes are unusable and a checked-in default registry exists, the
      default file is used as the baseline fallback.
    * With no usable source, public observer mode fails before dialing peers.
    """

    allow = public_testnet_allow_local() if allow_local is None else bool(allow_local)
    explicit_path = public_seed_registry_path(path)
    if explicit_path:
        try:
            return _load_public_seed_registry_file(explicit_path, allow_local=allow)
        except PublicSeedRegistryError:
            raise
        except Exception as exc:
            raise PublicSeedRegistryError(str(exc) or "public_seed_registry_invalid") from exc

    default_path = public_seed_registry_default_path()
    urls = public_seed_registry_urls(url)
    errors: list[str] = []

    attempts: list[Json] = []
    for candidate_url in urls:
        try:
            registry = _load_public_seed_registry_remote(candidate_url, allow_local=allow)
            attempts.append(
                {
                    "source_kind": "remote_url",
                    "provider": registry.get("registry_source_provider", "generic_https"),
                    "url": registry.get("registry_source", candidate_url),
                    "accepted": True,
                    "failure_code": "",
                }
            )
            registry["registry_mirror_attempts"] = attempts
            registry["provider_authority"] = False
            return registry
        except PublicSeedRegistryError as exc:
            code = str(exc) or "public_seed_registry_remote_error"
            attempts.append(
                {
                    "source_kind": "remote_url",
                    "provider": "generic_https",
                    "url": _safe_str(candidate_url),
                    "accepted": False,
                    "failure_code": code,
                }
            )
            errors.append(code)
            continue
        except Exception as exc:
            code = str(exc) or "public_seed_registry_remote_error"
            attempts.append(
                {
                    "source_kind": "remote_url",
                    "provider": "generic_https",
                    "url": _safe_str(candidate_url),
                    "accepted": False,
                    "failure_code": code,
                }
            )
            errors.append(code)
            continue

    if default_path:
        try:
            registry = _load_public_seed_registry_file(default_path, allow_local=allow)
            attempts.append(
                {
                    "source_kind": "file",
                    "provider": "local_file",
                    "url": str(Path(default_path).expanduser()),
                    "accepted": True,
                    "failure_code": "",
                }
            )
            registry["registry_mirror_attempts"] = attempts
            registry["provider_authority"] = False
            return registry
        except PublicSeedRegistryError as exc:
            code = str(exc) or "public_seed_registry_error"
            attempts.append(
                {
                    "source_kind": "file",
                    "provider": "local_file",
                    "url": str(Path(default_path).expanduser()),
                    "accepted": False,
                    "failure_code": code,
                }
            )
            errors.append(code)
        except Exception as exc:
            code = str(exc) or "public_seed_registry_error"
            attempts.append(
                {
                    "source_kind": "file",
                    "provider": "local_file",
                    "url": str(Path(default_path).expanduser()),
                    "accepted": False,
                    "failure_code": code,
                }
            )
            errors.append(code)

    if errors:
        # Keep the externally visible failure code stable and actionable.
        raise PublicSeedRegistryError(errors[-1])
    raise PublicSeedRegistryError("public_seed_registry_path_missing")


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


def verified_peer_uris_from_registry(registry: Json, *, include_seeds: bool = True, include_validators: bool = True) -> list[str]:
    """Return P2P peer URIs that are safe for public observer auto-dial.

    Seed P2P URLs are trusted only because the registry itself is verified or is
    a local unsigned rehearsal registry. Validator endpoint P2P URLs require a
    valid endpoint advertisement signature and never grant validator authority.
    """

    out: list[str] = []
    seen: set[str] = set()
    if include_seeds:
        for raw in registry.get("seed_p2p_urls") or []:
            uri = _safe_str(raw)
            if uri and uri not in seen:
                seen.add(uri)
                out.append(uri)
    if include_validators:
        for endpoint in registry.get("validator_endpoints") or []:
            if not isinstance(endpoint, dict) or endpoint.get("verified") is not True:
                continue
            uri = _safe_str(endpoint.get("p2p_url"))
            if uri and uri not in seen:
                seen.add(uri)
                out.append(uri)
    return out
