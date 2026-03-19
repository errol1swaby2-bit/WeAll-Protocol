from __future__ import annotations

import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

Json = dict[str, Any]
from weall.runtime.protocol_profile import PRODUCTION_CONSENSUS_PROFILE


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[3]


def _resolve_chain_config_path(chosen: str) -> Path:
    raw = str(chosen or "").strip()
    if not raw:
        raw = "./configs/dev.chain.json"
    candidate = Path(raw).expanduser()
    if candidate.is_absolute():
        return candidate
    if candidate.is_file():
        return candidate.resolve()
    repo_candidate = (_repo_root() / candidate).resolve()
    if repo_candidate.is_file():
        return repo_candidate
    return candidate


def _as_int(v: Any, default: int) -> int:
    try:
        return int(v)
    except Exception:
        return int(default)


def _as_str(v: Any, default: str) -> str:
    if v is None:
        return str(default)
    s = str(v)
    return s if s.strip() else str(default)


def _as_bool(v: Any, default: bool) -> bool:
    if v is None:
        return bool(default)
    if isinstance(v, bool):
        return v
    s = str(v).strip().lower()
    if s in {"1", "true", "yes", "y", "on"}:
        return True
    if s in {"0", "false", "no", "n", "off"}:
        return False
    return bool(default)


def _env_bool_status(name: str, default: bool) -> tuple[bool, bool]:
    raw = os.environ.get(name)
    if raw is None:
        return bool(default), False
    if isinstance(raw, bool):
        return bool(raw), False
    s = str(raw).strip().lower()
    if not s:
        return bool(default), False
    if s in {"1", "true", "yes", "y", "on"}:
        return True, False
    if s in {"0", "false", "no", "n", "off"}:
        return False, False
    return bool(default), True


def _env_int_status(name: str, default: int) -> tuple[int, bool]:
    raw = os.environ.get(name)
    if raw is None:
        return int(default), False
    s = str(raw).strip()
    if not s:
        return int(default), False
    try:
        return int(s), False
    except Exception:
        return int(default), True


def canon_json(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def chain_config_compatibility_payload(cfg: ChainConfig) -> Json:
    """Consensus-/interop-relevant subset for validator compatibility checks.

    This intentionally excludes local-only operator settings such as db_path,
    api binding, log level, and node_id. The goal is to detect configuration
    drift that would let a node start on the correct chain/profile yet still
    disagree about block production or transaction admission behavior.
    """
    return {
        "chain_id": str(cfg.chain_id or ""),
        "mode": str(cfg.mode or "").strip().lower(),
        "block_interval_ms": int(cfg.block_interval_ms),
        "max_txs_per_block": int(cfg.max_txs_per_block),
        "block_reward": int(cfg.block_reward),
        "allow_unsigned_txs": bool(cfg.allow_unsigned_txs),
    }


def chain_config_compatibility_hash(cfg: ChainConfig) -> str:
    from hashlib import sha256

    return sha256(canon_json(chain_config_compatibility_payload(cfg)).encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class ChainConfig:
    chain_id: str
    node_id: str
    mode: str  # "dev" | "testnet" | "prod"

    # Single SQLite DB file path for all node persistence.
    db_path: str
    tx_index_path: str

    block_interval_ms: int
    max_txs_per_block: int
    block_reward: int

    api_host: str
    api_port: int

    allow_unsigned_txs: bool

    log_level: str


def _secret_present(name: str) -> bool:
    v = str(os.environ.get(name, "") or "").strip()
    return bool(v)


def _secret_file_present(name: str) -> bool:
    fp = str(os.environ.get(name, "") or "").strip()
    if not fp:
        return False
    try:
        return Path(fp).is_file()
    except Exception:
        return False


def _db_parent_writable(db_path: str) -> bool:
    try:
        parent = Path(db_path).resolve().parent
        parent.mkdir(parents=True, exist_ok=True)
        probe = parent / ".weall_write_probe"
        probe.write_text("ok", encoding="utf-8")
        probe.unlink(missing_ok=True)
        return True
    except Exception:
        return False


def _trusted_anchor_env_status(default: bool = True) -> tuple[bool, bool, bool]:
    names = ("WEALL_SYNC_REQUIRE_TRUSTED_ANCHOR", "WEALL_STATE_SYNC_REQUIRE_TRUSTED_ANCHOR")
    seen: dict[str, bool] = {}
    invalid = False
    for name in names:
        value, bad = _env_bool_status(name, default)
        if os.environ.get(name) is None:
            continue
        seen[name] = bool(value)
        invalid = invalid or bool(bad)
    if not seen:
        return bool(default), False, invalid
    vals = set(seen.values())
    if len(vals) > 1:
        return bool(default), True, invalid
    return bool(next(iter(vals))), False, invalid


def _csv_values(name: str) -> list[str]:
    raw = str(os.environ.get(name, "") or "").strip()
    if not raw:
        return []
    return [part.strip() for part in raw.split(",") if part.strip()]


def _urls_all_https(urls: list[str]) -> bool:
    if not urls:
        return False
    for raw in urls:
        try:
            parsed = urlparse(str(raw))
        except Exception:
            return False
        if str(parsed.scheme or "").lower() != "https":
            return False
        if not str(parsed.netloc or "").strip():
            return False
    return True


def _urls_have_no_duplicates(urls: list[str]) -> bool:
    seen: set[str] = set()
    for raw in urls:
        normalized = str(raw).strip().rstrip("/").lower()
        if not normalized:
            return False
        if normalized in seen:
            return False
        seen.add(normalized)
    return True


def _json_file_is_object(path: str) -> bool:
    try:
        payload = json.loads(Path(path).read_text(encoding="utf-8"))
    except Exception:
        return False
    return isinstance(payload, dict)


def _node_identity_source_report() -> Json:
    return {
        "public_key_inline": _secret_present("WEALL_NODE_PUBKEY"),
        "public_key_file": _secret_file_present("WEALL_NODE_PUBKEY_FILE"),
        "private_key_inline": _secret_present("WEALL_NODE_PRIVKEY"),
        "private_key_file": _secret_file_present("WEALL_NODE_PRIVKEY_FILE"),
        "validator_account_inline": _secret_present("WEALL_VALIDATOR_ACCOUNT"),
        "validator_account_file": _secret_file_present("WEALL_VALIDATOR_ACCOUNT_FILE"),
    }


def production_bootstrap_issues(cfg: ChainConfig) -> list[str]:
    """Return operator-facing production bootstrap blockers.

    This is intentionally stricter than basic config validation. It checks the
    surrounding runtime posture required for an independent validator/public node
    to start fail-closed instead of silently degrading into an unsafe or
    non-diagnosable setup.
    """
    issues: list[str] = []
    validate_chain_config(cfg)

    mode = str(cfg.mode or "").strip().lower()
    if mode != "prod":
        return issues

    if not _db_parent_writable(cfg.db_path):
        issues.append(f"db_path parent is not writable: {cfg.db_path!r}")

    tx_index_path = Path(str(cfg.tx_index_path or "")).resolve()
    if not tx_index_path.is_file():
        issues.append(f"tx_index_path missing: {str(tx_index_path)!r}")
    elif not _json_file_is_object(str(tx_index_path)):
        issues.append(f"tx_index_path must be a valid JSON object file: {str(tx_index_path)!r}")

    net_enabled, net_enabled_invalid = _env_bool_status("WEALL_NET_ENABLED", False)
    bft_enabled, bft_enabled_invalid = _env_bool_status("WEALL_BFT_ENABLED", False)
    if net_enabled_invalid:
        issues.append("invalid_boolean_env:WEALL_NET_ENABLED")
    if bft_enabled_invalid:
        issues.append("invalid_boolean_env:WEALL_BFT_ENABLED")

    key_sources = _node_identity_source_report()
    pubkey_ok = bool(key_sources["public_key_inline"] or key_sources["public_key_file"])
    privkey_ok = bool(key_sources["private_key_inline"] or key_sources["private_key_file"])

    if net_enabled or bft_enabled:
        if not pubkey_ok:
            issues.append(
                "missing node public key: set WEALL_NODE_PUBKEY or WEALL_NODE_PUBKEY_FILE"
            )
        if not privkey_ok:
            issues.append(
                "missing node private key: set WEALL_NODE_PRIVKEY or WEALL_NODE_PRIVKEY_FILE"
            )

    if bft_enabled:
        validator_account = str(os.environ.get("WEALL_VALIDATOR_ACCOUNT", "") or "").strip()
        validator_account_file = str(
            os.environ.get("WEALL_VALIDATOR_ACCOUNT_FILE", "") or ""
        ).strip()
        if not validator_account and not (
            validator_account_file and Path(validator_account_file).is_file()
        ):
            issues.append(
                "missing validator account: set WEALL_VALIDATOR_ACCOUNT or WEALL_VALIDATOR_ACCOUNT_FILE"
            )

        sync_enforce_finalized_anchor, sync_enforce_finalized_anchor_invalid = _env_bool_status(
            "WEALL_SYNC_ENFORCE_FINALIZED_ANCHOR", True
        )
        if sync_enforce_finalized_anchor_invalid:
            issues.append("invalid_boolean_env:WEALL_SYNC_ENFORCE_FINALIZED_ANCHOR")
        elif not sync_enforce_finalized_anchor:
            issues.append(
                "WEALL_SYNC_ENFORCE_FINALIZED_ANCHOR must remain enabled when BFT is enabled in production"
            )

        raw_strict = os.environ.get("WEALL_BFT_STRICT_EPOCH_BINDING")
        if raw_strict is not None:
            strict_epoch_binding, strict_epoch_binding_invalid = _env_bool_status(
                "WEALL_BFT_STRICT_EPOCH_BINDING", True
            )
            if strict_epoch_binding_invalid:
                issues.append("invalid_boolean_env:WEALL_BFT_STRICT_EPOCH_BINDING")
            elif not strict_epoch_binding:
                issues.append(
                    "WEALL_BFT_STRICT_EPOCH_BINDING must remain enabled for production BFT nodes"
                )

        bft_fetch_enabled, bft_fetch_enabled_invalid = _env_bool_status(
            "WEALL_BFT_FETCH_ENABLED", True
        )
        if bft_fetch_enabled_invalid:
            issues.append("invalid_boolean_env:WEALL_BFT_FETCH_ENABLED")
        elif not bft_fetch_enabled:
            issues.append("WEALL_BFT_FETCH_ENABLED must remain enabled for production BFT nodes")
        fetch_sources = _csv_values("WEALL_BFT_FETCH_BASE_URLS")
        if not fetch_sources:
            issues.append(
                "missing BFT fetch sources: set WEALL_BFT_FETCH_BASE_URLS to one or more HTTPS base URLs"
            )
        elif not _urls_all_https(fetch_sources):
            issues.append(
                "WEALL_BFT_FETCH_BASE_URLS must contain only HTTPS base URLs in production"
            )
        elif not _urls_have_no_duplicates(fetch_sources):
            issues.append(
                "WEALL_BFT_FETCH_BASE_URLS must not contain duplicate base URLs in production"
            )

    if net_enabled:
        require_anchor, anchor_conflict, anchor_invalid = _trusted_anchor_env_status(True)
        if anchor_invalid:
            issues.append(
                "invalid_boolean_env:WEALL_SYNC_REQUIRE_TRUSTED_ANCHOR/WEALL_STATE_SYNC_REQUIRE_TRUSTED_ANCHOR"
            )
        elif anchor_conflict:
            issues.append(
                "trusted-anchor env aliases conflict: WEALL_SYNC_REQUIRE_TRUSTED_ANCHOR vs WEALL_STATE_SYNC_REQUIRE_TRUSTED_ANCHOR"
            )
        elif not require_anchor:
            issues.append("TRUSTED_ANCHOR requirement must remain enabled in production networking")

        peer_id = str(os.environ.get("WEALL_PEER_ID", "") or "").strip()
        if not peer_id or peer_id == "local":
            issues.append(
                "missing explicit peer id: set WEALL_PEER_ID to a stable non-default value"
            )

        net_require_peer_identity, net_require_peer_identity_invalid = _env_bool_status(
            "WEALL_NET_REQUIRE_PEER_IDENTITY", True
        )
        if net_require_peer_identity_invalid:
            issues.append("invalid_boolean_env:WEALL_NET_REQUIRE_PEER_IDENTITY")
        elif not net_require_peer_identity:
            issues.append(
                "WEALL_NET_REQUIRE_PEER_IDENTITY must remain enabled in production networking"
            )

        net_require_identity, net_require_identity_invalid = _env_bool_status(
            "WEALL_NET_REQUIRE_IDENTITY", True
        )
        if net_require_identity_invalid:
            issues.append("invalid_boolean_env:WEALL_NET_REQUIRE_IDENTITY")
        elif not net_require_identity:
            issues.append("WEALL_NET_REQUIRE_IDENTITY must remain enabled in production networking")

        if bft_enabled:
            net_require_identity_for_bft, net_require_identity_for_bft_invalid = _env_bool_status(
                "WEALL_NET_REQUIRE_IDENTITY_FOR_BFT", True
            )
            if net_require_identity_for_bft_invalid:
                issues.append("invalid_boolean_env:WEALL_NET_REQUIRE_IDENTITY_FOR_BFT")
            elif not net_require_identity_for_bft:
                issues.append(
                    "WEALL_NET_REQUIRE_IDENTITY_FOR_BFT must remain enabled for production BFT nodes"
                )

        sync_require_header_match, sync_require_header_match_invalid = _env_bool_status(
            "WEALL_SYNC_REQUIRE_HEADER_MATCH", True
        )
        if sync_require_header_match_invalid:
            issues.append("invalid_boolean_env:WEALL_SYNC_REQUIRE_HEADER_MATCH")
        elif not sync_require_header_match:
            issues.append(
                "WEALL_SYNC_REQUIRE_HEADER_MATCH must remain enabled in production networking"
            )

    block_loop_autostart, block_loop_autostart_invalid = _env_bool_status(
        "WEALL_BLOCK_LOOP_AUTOSTART", False
    )
    net_loop_autostart, net_loop_autostart_invalid = _env_bool_status(
        "WEALL_NET_LOOP_AUTOSTART", False
    )
    if block_loop_autostart_invalid:
        issues.append("invalid_boolean_env:WEALL_BLOCK_LOOP_AUTOSTART")
    if net_loop_autostart_invalid:
        issues.append("invalid_boolean_env:WEALL_NET_LOOP_AUTOSTART")
    if bft_enabled and block_loop_autostart:
        issues.append(
            "WEALL_BFT_ENABLED=1 cannot be combined with WEALL_BLOCK_LOOP_AUTOSTART=1 in production"
        )

    from weall.runtime.bootstrap_manifest import (
        release_manifest_path,
        release_pubkey,
        signed_manifest_required,
        verify_local_manifest,
    )

    manifest_required = signed_manifest_required(
        mode=mode, network_enabled=bool(net_enabled), bft_enabled=bool(bft_enabled)
    )
    manifest_path_raw = release_manifest_path()
    manifest_pubkey = release_pubkey()
    manifest_report = None
    if manifest_required:
        if not manifest_path_raw:
            issues.append("missing signed release manifest: set WEALL_RELEASE_MANIFEST_PATH")
        elif not Path(manifest_path_raw).is_file():
            issues.append(f"release manifest not found: {manifest_path_raw!r}")
        if not manifest_pubkey:
            issues.append(
                "missing release manifest signer pubkey: set WEALL_RELEASE_PUBKEY or WEALL_RELEASE_PUBKEY_FILE"
            )
    if manifest_path_raw and manifest_pubkey and Path(manifest_path_raw).is_file():
        try:
            manifest_report = verify_local_manifest(
                cfg=cfg,
                manifest_path=Path(manifest_path_raw).resolve(),
                expected_pubkey=manifest_pubkey,
            )
            issues.extend(list(manifest_report.get("issues") or []))
        except Exception as exc:
            issues.append(f"release manifest verification failed: {exc}")

    startup_clock_sanity_required, startup_clock_sanity_required_invalid = _env_bool_status(
        "WEALL_STARTUP_CLOCK_SANITY_REQUIRED",
        PRODUCTION_CONSENSUS_PROFILE.startup_clock_sanity_required,
    )
    if startup_clock_sanity_required_invalid:
        issues.append("invalid_boolean_env:WEALL_STARTUP_CLOCK_SANITY_REQUIRED")

    workers, workers_invalid = _env_int_status("GUNICORN_WORKERS", 1)
    if workers_invalid:
        issues.append("invalid_integer_env:GUNICORN_WORKERS")
    if (block_loop_autostart or net_loop_autostart or bft_enabled or net_enabled) and workers > 1:
        issues.append(
            "GUNICORN_WORKERS must be 1 when networking/consensus autostart loops are enabled in production"
        )

    sigverify = str(os.environ.get("WEALL_SIGVERIFY", "") or "").strip()
    if sigverify == "0":
        issues.append("WEALL_SIGVERIFY=0 is not allowed for production nodes")

    return issues


def production_bootstrap_report(cfg: ChainConfig) -> Json:
    """Structured operator-facing bootstrap posture summary."""
    issues = production_bootstrap_issues(cfg)
    fetch_sources = _csv_values("WEALL_BFT_FETCH_BASE_URLS")
    require_anchor, anchor_conflict, anchor_invalid = _trusted_anchor_env_status(True)
    net_enabled, net_enabled_invalid = _env_bool_status("WEALL_NET_ENABLED", False)
    bft_enabled, bft_enabled_invalid = _env_bool_status("WEALL_BFT_ENABLED", False)
    from weall.runtime.bootstrap_manifest import (
        release_manifest_path,
        release_pubkey,
        signed_manifest_required,
        verify_local_manifest,
    )

    manifest_required = signed_manifest_required(
        mode=str(cfg.mode or "").strip().lower(),
        network_enabled=bool(net_enabled),
        bft_enabled=bool(bft_enabled),
    )
    manifest_path_raw = release_manifest_path()
    manifest_pubkey = release_pubkey()
    manifest_report = None
    if manifest_path_raw and manifest_pubkey and Path(manifest_path_raw).is_file():
        try:
            manifest_report = verify_local_manifest(
                cfg=cfg,
                manifest_path=Path(manifest_path_raw).resolve(),
                expected_pubkey=manifest_pubkey,
            )
        except Exception as exc:
            manifest_report = {
                "ok": False,
                "path": manifest_path_raw,
                "pubkey": manifest_pubkey,
                "issues": [f"release manifest verification failed: {exc}"],
            }
    return {
        "ok": not issues,
        "mode": str(cfg.mode or "").strip().lower(),
        "chain_id": str(cfg.chain_id or ""),
        "node_id": str(cfg.node_id or ""),
        "db_path": str(cfg.db_path or ""),
        "tx_index_path": str(cfg.tx_index_path or ""),
        "network_enabled": bool(net_enabled),
        "bft_enabled": bool(bft_enabled),
        "network_enabled_env_invalid": bool(net_enabled_invalid),
        "bft_enabled_env_invalid": bool(bft_enabled_invalid),
        "trusted_anchor_required": bool(require_anchor),
        "protocol_version": str(PRODUCTION_CONSENSUS_PROFILE.protocol_version),
        "protocol_profile_hash": str(PRODUCTION_CONSENSUS_PROFILE.profile_hash()),
        "startup_clock_sanity_required": bool(
            PRODUCTION_CONSENSUS_PROFILE.startup_clock_sanity_required
        ),
        "startup_clock_hard_fail_ms": int(PRODUCTION_CONSENSUS_PROFILE.startup_clock_hard_fail_ms),
        "trusted_anchor_env_conflict": bool(anchor_conflict),
        "trusted_anchor_env_invalid": bool(anchor_invalid),
        "fetch_sources": fetch_sources,
        "fetch_sources_https_only": _urls_all_https(fetch_sources) if fetch_sources else False,
        "fetch_sources_unique": _urls_have_no_duplicates(fetch_sources) if fetch_sources else False,
        "identity_sources": _node_identity_source_report(),
        "signed_release_manifest_required": bool(manifest_required),
        "release_manifest_path": manifest_path_raw,
        "release_manifest_pubkey_present": bool(manifest_pubkey),
        "release_manifest": manifest_report,
        "observer_first_recommended": True,
        "recommended_join_mode": "observer_first_then_verify_then_enable_bft_signing",
        "issues": issues,
    }


_ALLOWED_MODES = {"dev", "testnet", "prod"}


def validate_chain_config(cfg: ChainConfig) -> None:
    """Fail-fast validation for operator config.

    Prevent silent misconfiguration that could put a node into an unsafe
    posture or an unusable state.
    """

    if not isinstance(cfg.chain_id, str) or not cfg.chain_id.strip():
        raise ValueError("chain_id must be a non-empty string")

    if not isinstance(cfg.node_id, str) or not cfg.node_id.strip():
        raise ValueError("node_id must be a non-empty string")

    mode = str(cfg.mode or "").strip().lower()
    if mode not in _ALLOWED_MODES:
        raise ValueError(f"mode must be one of {sorted(_ALLOWED_MODES)}")

    if not isinstance(cfg.db_path, str) or not cfg.db_path.strip():
        raise ValueError("db_path must be a non-empty string")

    if not isinstance(cfg.tx_index_path, str) or not cfg.tx_index_path.strip():
        raise ValueError("tx_index_path must be a non-empty string")

    if int(cfg.block_interval_ms) <= 0:
        raise ValueError("block_interval_ms must be > 0")

    if int(cfg.max_txs_per_block) <= 0:
        raise ValueError("max_txs_per_block must be > 0")

    if int(cfg.block_reward) < 0:
        raise ValueError("block_reward must be >= 0")

    if not isinstance(cfg.api_host, str) or not cfg.api_host.strip():
        raise ValueError("api_host must be a non-empty string")

    if not (1 <= int(cfg.api_port) <= 65535):
        raise ValueError("api_port must be between 1 and 65535")

    if not isinstance(cfg.allow_unsigned_txs, bool):
        raise ValueError("allow_unsigned_txs must be a boolean")

    if mode == "prod" and bool(cfg.allow_unsigned_txs):
        raise ValueError("allow_unsigned_txs must be false in prod")

    if not isinstance(cfg.log_level, str) or not cfg.log_level.strip():
        raise ValueError("log_level must be a non-empty string")


def _read_json_file(path: Path) -> Json:
    if not path.is_file():
        raise FileNotFoundError(f"chain config not found: {path}")
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError("chain config must be a JSON object")
    return data


def load_chain_config(path: str | None = None) -> ChainConfig:
    env_path = os.environ.get("WEALL_CHAIN_CONFIG_PATH", "").strip()
    chosen = path or env_path or "./configs/dev.chain.json"
    resolved = _resolve_chain_config_path(chosen)
    if resolved.is_file():
        payload = _read_json_file(resolved)
    else:
        # Fail closed for explicit operator-provided paths, but keep test/dev
        # runtime bootstrap ergonomic by allowing the historical built-in dev
        # defaults when no config file was explicitly requested.
        if path or env_path:
            raise FileNotFoundError(f"chain config not found: {resolved}")
        payload = {}
    cfg = ChainConfig(
        chain_id=_as_str(payload.get("chain_id"), "weall-dev"),
        node_id=_as_str(payload.get("node_id"), "node-1"),
        mode=_as_str(payload.get("mode"), "dev"),
        db_path=_as_str(payload.get("db_path"), "./data/weall.db"),
        tx_index_path=_as_str(payload.get("tx_index_path"), "./generated/tx_index.json"),
        block_interval_ms=_as_int(payload.get("block_interval_ms"), 600_000),
        max_txs_per_block=_as_int(payload.get("max_txs_per_block"), 1000),
        block_reward=_as_int(payload.get("block_reward"), 0),
        api_host=_as_str(payload.get("api_host"), "127.0.0.1"),
        api_port=_as_int(payload.get("api_port"), 8000),
        allow_unsigned_txs=_as_bool(payload.get("allow_unsigned_txs"), False),
        log_level=_as_str(payload.get("log_level"), "INFO"),
    )
    validate_chain_config(cfg)
    return cfg
