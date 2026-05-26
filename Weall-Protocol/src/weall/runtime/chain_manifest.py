from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

Json = dict[str, Any]

CHAIN_MANIFEST_ENV_NAMES: tuple[str, str] = (
    "WEALL_CHAIN_MANIFEST_PATH",
    "WEALL_CHAIN_MANIFEST",
)

DEFAULT_PRODUCTION_CHAIN_MANIFEST_PATH = "./configs/chains/weall-genesis.json"
DEFAULT_DEMO_CHAIN_MANIFEST_PATH = "./configs/chains/weall-demo.json"

_PLACEHOLDER_PREFIXES: tuple[str, ...] = (
    "replace",
    "replace_",
    "replace-with",
    "put_",
    "put-",
    "todo",
    "tbd",
    "pending",
)


@dataclass(frozen=True, slots=True)
class ChainManifest:
    """Pinned chain identity manifest used by nodes and authority-aware tooling."""

    path: str
    version: int
    chain_id: str
    profile: str
    mode: str
    schema_version: str
    genesis_hash: str
    genesis_state_root: str
    tx_index_hash: str
    protocol_profile_hash: str
    constitution_version: str
    constitution_hash: str
    constitution_traceability_hash: str
    constitution_document_path: str
    authority_snapshot_version: int
    trusted_authority_pubkeys: tuple[str, ...]
    raw: Json
    manifest_hash: str


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[3]


def canonical_json(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def sha256_hex(data: bytes | str) -> str:
    if isinstance(data, str):
        data = data.encode("utf-8")
    return hashlib.sha256(data).hexdigest()


def _resolve_path(raw: str) -> Path:
    s = str(raw or "").strip()
    if not s:
        raise ValueError("missing_chain_manifest_path")
    candidate = Path(s).expanduser()
    if candidate.is_absolute():
        return candidate
    if candidate.exists():
        return candidate.resolve()
    return (_repo_root() / candidate).resolve()


def _env_mode() -> str:
    return str(os.environ.get("WEALL_MODE", "") or "").strip().lower()


def _runtime_profile() -> str:
    return str(os.environ.get("WEALL_RUNTIME_PROFILE", "") or "").strip().lower()


def _authority_profile() -> str:
    return str(os.environ.get("WEALL_AUTHORITY_PROFILE", "") or "").strip().lower()


def _env_manifest_path() -> str:
    for name in CHAIN_MANIFEST_ENV_NAMES:
        raw = str(os.environ.get(name, "") or "").strip()
        if raw:
            return raw
    return ""


def default_chain_manifest_path_for_mode(mode: str | None = None) -> str:
    m = str(mode or _env_mode() or "").strip().lower()
    profile = _runtime_profile()
    authority_profile = _authority_profile()
    if m in {"demo", "seeded_demo"} or profile == "seeded_demo" or authority_profile == "demo":
        return DEFAULT_DEMO_CHAIN_MANIFEST_PATH
    if m in {"prod", "production", "production_like"}:
        return DEFAULT_PRODUCTION_CHAIN_MANIFEST_PATH
    return ""


def _truthy_env(name: str, default: str = "0") -> bool:
    return str(os.environ.get(name, default) or default).strip().lower() in {
        "1",
        "true",
        "yes",
        "y",
        "on",
    }


def _pytest_prod_fixture_uses_noncanonical_chain() -> bool:
    """Return true for pytest-local prod fixtures that intentionally use
    throwaway chain IDs/configs.

    Real production starts still get the checked-in production manifest by
    default.  Several older fail-closed API/config tests run with
    WEALL_MODE=prod and WEALL_CHAIN_ID=weall-test only to exercise startup
    ordering; they are not production chain-identity tests.
    """
    if not os.environ.get("PYTEST_CURRENT_TEST"):
        return False
    chain_id = str(os.environ.get("WEALL_CHAIN_ID", "") or "").strip()
    if not chain_id:
        return True
    return chain_id not in {"weall-prod", "weall-main", "weall-genesis"}


def active_chain_manifest_path(*, mode: str | None = None, explicit_only: bool = False) -> str:
    explicit = _env_manifest_path()
    if explicit:
        return explicit
    if explicit_only:
        return ""

    normalized_mode = str(mode or _env_mode() or "").strip().lower()
    if normalized_mode in {"prod", "production", "production_like"}:
        # Production must fail closed around a pinned chain identity even when an
        # operator bypasses the shell wrappers and imports/boots the Python app
        # directly.  The checked-in canonical genesis manifest is safe to use as
        # the implicit production default for the default production config.
        # Explicit custom chain-config files and pytest-local non-canonical prod
        # fixtures must provide their own manifest path when they want manifest
        # validation.
        if str(os.environ.get("WEALL_CHAIN_CONFIG_PATH", "") or "").strip():
            return ""
        if _pytest_prod_fixture_uses_noncanonical_chain() and not _truthy_env("WEALL_REQUIRE_CHAIN_MANIFEST"):
            return ""
        return default_chain_manifest_path_for_mode(normalized_mode)

    if _truthy_env("WEALL_USE_DEFAULT_CHAIN_MANIFEST") or _truthy_env("WEALL_REQUIRE_CHAIN_MANIFEST"):
        return default_chain_manifest_path_for_mode(mode)
    return ""


def _read_json(path: Path) -> Json:
    obj = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(obj, dict):
        raise ValueError("chain_manifest_must_be_json_object")
    return obj


def _normalized_pubkeys(obj: Mapping[str, Any]) -> tuple[str, ...]:
    values = obj.get("trusted_authority_pubkeys", [])
    if not isinstance(values, list):
        return ()
    return tuple(sorted({str(v).strip().lower() for v in values if str(v or "").strip()}))


def _safe_int(value: Any, default: int = 0) -> int:
    try:
        if value is None or isinstance(value, bool):
            return int(default)
        return int(value)
    except Exception:
        return int(default)


def _manifest_payload_for_hash(obj: Mapping[str, Any]) -> Json:
    return {str(k): v for k, v in dict(obj).items() if str(k) != "manifest_hash"}


def compute_chain_manifest_hash(obj: Mapping[str, Any]) -> str:
    return sha256_hex(canonical_json(_manifest_payload_for_hash(obj)))


def load_chain_manifest(
    path: str | None = None,
    *,
    required: bool = False,
    mode: str | None = None,
) -> ChainManifest | None:
    raw = str(path or active_chain_manifest_path(mode=mode) or "").strip()
    if not raw:
        if required:
            raise FileNotFoundError("chain manifest path not configured")
        return None
    resolved = _resolve_path(raw)
    if not resolved.is_file():
        if required:
            raise FileNotFoundError(f"chain manifest not found: {resolved}")
        return None

    obj = _read_json(resolved)
    mh = compute_chain_manifest_hash(obj)
    return ChainManifest(
        path=str(resolved),
        version=_safe_int(obj.get("version"), 1),
        chain_id=str(obj.get("chain_id") or "").strip(),
        profile=str(obj.get("profile") or "").strip(),
        mode=str(obj.get("mode") or "").strip().lower(),
        schema_version=str(obj.get("schema_version") or "").strip(),
        genesis_hash=str(obj.get("genesis_hash") or "").strip().lower(),
        genesis_state_root=str(obj.get("genesis_state_root") or "").strip().lower(),
        tx_index_hash=str(obj.get("tx_index_hash") or "").strip().lower(),
        protocol_profile_hash=str(obj.get("protocol_profile_hash") or "").strip().lower(),
        constitution_version=str(obj.get("constitution_version") or (obj.get("constitution") if isinstance(obj.get("constitution"), dict) else {}).get("version") or "").strip(),
        constitution_hash=str(obj.get("constitution_hash") or (obj.get("constitution") if isinstance(obj.get("constitution"), dict) else {}).get("hash") or "").strip().lower(),
        constitution_traceability_hash=str(obj.get("constitution_traceability_hash") or (obj.get("constitution") if isinstance(obj.get("constitution"), dict) else {}).get("traceability_hash") or "").strip().lower(),
        constitution_document_path=str(obj.get("constitution_document_path") or (obj.get("constitution") if isinstance(obj.get("constitution"), dict) else {}).get("document_path") or "").strip(),
        authority_snapshot_version=_safe_int(obj.get("authority_snapshot_version"), 1),
        trusted_authority_pubkeys=_normalized_pubkeys(obj),
        raw=dict(obj),
        manifest_hash=mh,
    )


def is_placeholder(value: Any) -> bool:
    s = str(value or "").strip().lower()
    if not s:
        return True
    return any(s.startswith(prefix) for prefix in _PLACEHOLDER_PREFIXES)


def _is_hex_string(value: Any, *, length: int | None = None) -> bool:
    s = str(value or "").strip().lower()
    if not s:
        return False
    if length is not None and len(s) != int(length):
        return False
    try:
        int(s, 16)
    except Exception:
        return False
    return True


def _manifest_strict_profile_required(manifest: ChainManifest) -> bool:
    mode = str(manifest.mode or "").strip().lower()
    profile = str(manifest.profile or "").strip().lower()
    return mode in {"prod", "production"} or profile in {"production", "production_service"}


def file_canonical_json_hash(path: str | Path) -> str:
    # Match WeAllExecutor.tx_index_hash(): raw file bytes, not parsed JSON.
    return sha256_hex(Path(path).read_bytes())


def _manifest_summary(manifest: ChainManifest | None) -> Json:
    if manifest is None:
        return {"enabled": False}
    return {
        "enabled": True,
        "path": manifest.path,
        "version": manifest.version,
        "chain_id": manifest.chain_id,
        "profile": manifest.profile,
        "mode": manifest.mode,
        "schema_version": manifest.schema_version,
        "genesis_hash": manifest.genesis_hash,
        "genesis_state_root": manifest.genesis_state_root,
        "tx_index_hash": manifest.tx_index_hash,
        "protocol_profile_hash": manifest.protocol_profile_hash,
        "constitution_version": manifest.constitution_version,
        "constitution_hash": manifest.constitution_hash,
        "constitution_traceability_hash": manifest.constitution_traceability_hash,
        "constitution_document_path": manifest.constitution_document_path,
        "authority_snapshot_version": manifest.authority_snapshot_version,
        "trusted_authority_pubkeys_count": len(manifest.trusted_authority_pubkeys),
        "manifest_hash": manifest.manifest_hash,
    }


def chain_manifest_issues(
    *,
    manifest: ChainManifest | None,
    chain_id: str = "",
    mode: str = "",
    tx_index_path: str = "",
    schema_version: str = "",
    state_root: str = "",
    genesis_hash: str = "",
    strict: bool = False,
) -> list[str]:
    issues: list[str] = []
    if manifest is None:
        if strict:
            issues.append("chain_manifest_missing")
        return issues

    expected_chain_id = str(manifest.chain_id or "").strip()
    actual_chain_id = str(chain_id or "").strip()
    if not expected_chain_id:
        issues.append("chain_manifest_missing_chain_id")
    elif actual_chain_id and actual_chain_id != expected_chain_id:
        issues.append("chain_manifest_chain_id_mismatch")

    expected_mode = str(manifest.mode or "").strip().lower()
    actual_mode = str(mode or "").strip().lower()
    if expected_mode and actual_mode and expected_mode != actual_mode:
        issues.append("chain_manifest_mode_mismatch")

    expected_schema = str(manifest.schema_version or "").strip()
    actual_schema = str(schema_version or "").strip()
    if expected_schema and actual_schema and actual_schema != expected_schema:
        issues.append("chain_manifest_schema_version_mismatch")

    if is_placeholder(manifest.tx_index_hash):
        if strict:
            issues.append("chain_manifest_tx_index_hash_unpinned")
    elif tx_index_path:
        try:
            actual_tx_index_hash = file_canonical_json_hash(tx_index_path)
        except Exception:
            actual_tx_index_hash = ""
        if actual_tx_index_hash and actual_tx_index_hash.lower() != manifest.tx_index_hash.lower():
            issues.append("chain_manifest_tx_index_hash_mismatch")

    if is_placeholder(manifest.genesis_hash):
        if strict:
            issues.append("chain_manifest_genesis_hash_unpinned")
    elif genesis_hash and str(genesis_hash).strip().lower() != manifest.genesis_hash.lower():
        issues.append("chain_manifest_genesis_hash_mismatch")

    if is_placeholder(manifest.genesis_state_root):
        if strict:
            issues.append("chain_manifest_genesis_state_root_unpinned")
    elif state_root and str(state_root).strip().lower() != manifest.genesis_state_root.lower():
        issues.append("chain_manifest_genesis_state_root_mismatch")

    if strict:
        profile_required = _manifest_strict_profile_required(manifest)
        if profile_required and is_placeholder(manifest.protocol_profile_hash):
            issues.append("chain_manifest_protocol_profile_hash_unpinned")
        elif manifest.protocol_profile_hash and not _is_hex_string(manifest.protocol_profile_hash, length=64):
            issues.append("chain_manifest_protocol_profile_hash_invalid")

        if is_placeholder(manifest.constitution_version):
            issues.append("chain_manifest_constitution_version_unpinned")
        if is_placeholder(manifest.constitution_hash):
            issues.append("chain_manifest_constitution_hash_unpinned")
        elif not _is_hex_string(manifest.constitution_hash, length=64):
            issues.append("chain_manifest_constitution_hash_invalid")
        if manifest.constitution_traceability_hash and not _is_hex_string(manifest.constitution_traceability_hash, length=64):
            issues.append("chain_manifest_constitution_traceability_hash_invalid")

        if not manifest.trusted_authority_pubkeys:
            issues.append("chain_manifest_trusted_authority_pubkeys_missing")
        else:
            for pubkey in manifest.trusted_authority_pubkeys:
                if is_placeholder(pubkey):
                    issues.append("chain_manifest_trusted_authority_pubkey_unpinned")
                    break
                if not _is_hex_string(pubkey, length=64):
                    issues.append("chain_manifest_trusted_authority_pubkey_invalid")
                    break

    return issues


def chain_manifest_status(
    *,
    manifest: ChainManifest | None,
    chain_id: str = "",
    mode: str = "",
    tx_index_path: str = "",
    schema_version: str = "",
    state_root: str = "",
    genesis_hash: str = "",
    strict: bool = False,
) -> Json:
    out = _manifest_summary(manifest)
    out["issues"] = chain_manifest_issues(
        manifest=manifest,
        chain_id=chain_id,
        mode=mode,
        tx_index_path=tx_index_path,
        schema_version=schema_version,
        state_root=state_root,
        genesis_hash=genesis_hash,
        strict=strict,
    )
    out["ok"] = bool(out.get("enabled")) and not bool(out["issues"])
    if manifest is not None and tx_index_path:
        try:
            actual_hash = file_canonical_json_hash(tx_index_path)
        except Exception:
            actual_hash = ""
        out["actual_tx_index_hash"] = actual_hash
        out["tx_index_hash_matches"] = bool(
            actual_hash and manifest.tx_index_hash and actual_hash.lower() == manifest.tx_index_hash.lower()
        )
    if manifest is not None and state_root:
        out["state_root_matches_manifest_genesis"] = bool(
            manifest.genesis_state_root
            and not is_placeholder(manifest.genesis_state_root)
            and str(state_root).strip().lower() == manifest.genesis_state_root.lower()
        )
    return out
