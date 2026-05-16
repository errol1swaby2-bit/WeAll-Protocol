#!/usr/bin/env python3
"""Verify a public node-operator onboarding bundle.

This checker validates that the bundle is public-only, matches the expected
chain manifest when one is supplied, and can be converted into safe shell exports
for normal node-operator preflight scripts.
"""
from __future__ import annotations

import argparse
import json
import re
import shlex
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
Json = dict[str, Any]

SECRET_KEY_PATTERNS = re.compile(r"(privkey|private[_-]?key|secret|api[_-]?key|token|password)", re.IGNORECASE)
ALLOWED_PUBLIC_KEY_NAMES = {
    "trusted_authority_pubkeys",
    "pubkey",
    "pubkeys",
    "node_pubkey",
    "authority_pubkeys",
}
PLACEHOLDER_AUTHORITY_PUBKEYS = {
    "REPLACE_WITH_PRODUCTION_AUTHORITY_PUBKEY_HEX".lower(),
    "".lower(),
}

SAFE_OBSERVER_LIFECYCLE_STATES = {"observer_onboarding", "bootstrap_registration"}
SAFE_ONBOARDING_TXS = {
    "ACCOUNT_REGISTER",
    "ACCOUNT_KEY_ADD",
    "ACCOUNT_DEVICE_REGISTER",
    "ACCOUNT_SESSION_KEY_ISSUE",
    "PEER_ADVERTISE",
    "PEER_REQUEST_CONNECT",
    "PEER_RENDEZVOUS_TICKET_CREATE",
    "PEER_RENDEZVOUS_TICKET_REVOKE",
    "POH_APPLICATION_SUBMIT",
    "POH_EVIDENCE_DECLARE",
    "POH_EVIDENCE_BIND",
    "POH_ASYNC_REQUEST_OPEN",
    "POH_ASYNC_EVIDENCE_DECLARE",
    "POH_ASYNC_EVIDENCE_BIND",
}


def _json_dumps(data: Any) -> str:
    return json.dumps(data, separators=(",", ":"), sort_keys=True)


def _load_json(path: Path) -> Json:
    parsed = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(parsed, dict):
        raise RuntimeError(f"json_not_object:{path}")
    return parsed


def _walk_secret_keys(value: Any, path: str = "") -> list[str]:
    if path == "secret_boundary" or path.startswith("secret_boundary."):
        return []
    issues: list[str] = []
    if isinstance(value, dict):
        for key, child in value.items():
            key_s = str(key)
            child_path = f"{path}.{key_s}" if path else key_s
            if child_path == "secret_boundary" or child_path.startswith("secret_boundary."):
                continue
            if SECRET_KEY_PATTERNS.search(key_s) and key_s not in ALLOWED_PUBLIC_KEY_NAMES:
                issues.append(f"secret_like_key:{child_path}")
            issues.extend(_walk_secret_keys(child, child_path))
    elif isinstance(value, list):
        for idx, child in enumerate(value):
            issues.extend(_walk_secret_keys(child, f"{path}[{idx}]"))
    return issues


def _chain(bundle: Json) -> Json:
    chain = bundle.get("chain")
    return chain if isinstance(chain, dict) else {}


def _authority(bundle: Json) -> Json:
    """Return the public chain-authority section.

    New bundles should use ``authority``. A read-only fallback accepts the old
    ``oracle`` section for already-exported operator bundles, but generated shell
    env now uses provider-neutral authority names.
    """
    authority = bundle.get("authority")
    if isinstance(authority, dict):
        return authority
    legacy_authority = bundle.get("oracle")
    return legacy_authority if isinstance(legacy_authority, dict) else {}


def _observer(bundle: Json) -> Json:
    observer = bundle.get("observer")
    return observer if isinstance(observer, dict) else {}


def _relay_recipient_pubkeys(bundle: Json) -> dict[str, str]:
    raw = _observer(bundle).get("relay_recipient_pubkeys")
    if not isinstance(raw, dict):
        return {}
    out: dict[str, str] = {}
    for key, value in raw.items():
        k = str(key or "").strip()
        v = str(value or "").strip().lower()
        if k and v:
            out[k] = v
    return out


def _bool_is(value: Any, expected: bool) -> bool:
    return isinstance(value, bool) and value is expected


def _service_roles_empty(value: Any) -> bool:
    if value in (None, ""):
        return True
    if isinstance(value, list):
        return not any(str(item or "").strip() for item in value)
    if isinstance(value, str):
        return not any(part.strip() for part in value.split(","))
    return False


def _validate_observer_posture(bundle: Json) -> list[str]:
    """Validate that a public onboarding bundle cannot request service authority.

    This is intentionally stricter than ordinary JSON-shape validation because
    operators commonly run ``--emit-shell-env`` and then boot from those exports.
    A corrupted bundle must be rejected, not converted into an unsafe shell.
    """
    issues: list[str] = []
    observer = _observer(bundle)
    if not observer:
        return ["missing_observer_section"]

    if not _bool_is(observer.get("observer_mode_required"), True):
        issues.append("observer_mode_required_must_be_true")
    lifecycle = str(observer.get("node_lifecycle_state") or "").strip()
    if lifecycle not in SAFE_OBSERVER_LIFECYCLE_STATES:
        issues.append("observer_node_lifecycle_state_not_safe")
    if not _service_roles_empty(observer.get("service_roles")):
        issues.append("observer_service_roles_must_be_empty")
    if not _bool_is(observer.get("validator_signing_enabled"), False):
        issues.append("observer_validator_signing_must_be_false")
    if not _bool_is(observer.get("bft_enabled"), False):
        issues.append("observer_bft_must_be_false")
    if not _bool_is(observer.get("helper_authority_enabled"), False):
        issues.append("observer_helper_authority_must_be_false")
    if not _bool_is(observer.get("block_loop_autostart"), False):
        issues.append("observer_block_loop_autostart_must_be_false")

    allowed = observer.get("allowed_onboarding_transactions")
    if allowed is not None:
        if not isinstance(allowed, list):
            issues.append("observer_allowed_onboarding_transactions_not_list")
        else:
            unsafe = sorted({str(tx or "").strip() for tx in allowed if str(tx or "").strip() and str(tx or "").strip() not in SAFE_ONBOARDING_TXS})
            if unsafe:
                issues.append("observer_allowed_onboarding_transactions_unsafe:" + ",".join(unsafe))
    return issues


def _validate_relay_recipient_pubkeys(bundle: Json) -> list[str]:
    issues: list[str] = []
    observer = _observer(bundle)
    relay_urls = observer.get("relay_urls") if isinstance(observer.get("relay_urls"), list) else []
    mapping = _relay_recipient_pubkeys(bundle)
    if relay_urls and not mapping:
        issues.append("relay_recipient_pubkeys_required_when_relay_urls_present")
        return issues
    for peer_id, pubkey in mapping.items():
        if not peer_id.strip():
            issues.append("relay_recipient_pubkey_empty_peer_id")
        if not re.fullmatch(r"[0-9a-f]{64}", pubkey):
            issues.append(f"relay_recipient_pubkey_invalid:{peer_id}")
    return issues


def _validate(bundle: Json, manifest: Json | None, *, allow_placeholder_authority: bool) -> Json:
    issues: list[str] = []
    warnings: list[str] = []

    if bundle.get("type") != "weall_node_operator_onboarding_bundle":
        issues.append("bundle_wrong_type")
    if int(bundle.get("version") or 0) != 1:
        issues.append("bundle_wrong_version")

    chain = _chain(bundle)
    authority = _authority(bundle)
    required_chain = ["chain_id", "genesis_hash", "genesis_state_root", "tx_index_hash", "schema_version"]
    for key in required_chain:
        if not str(chain.get(key) or "").strip():
            issues.append(f"missing_chain_{key}")
    modern_observer_bundle = isinstance(bundle.get("observer"), dict) or "authority" in bundle
    if modern_observer_bundle and str(bundle.get("profile") or "").lower() in {"prod", "production", "production_service"}:
        if not str(chain.get("protocol_profile_hash") or "").strip():
            issues.append("missing_chain_protocol_profile_hash")

    if str(bundle.get("profile") or "").lower() in {"prod", "production", "production_service"}:
        if str(authority.get("profile") or "") != "production":
            issues.append("production_bundle_authority_profile_not_production")
        authority_url = str(authority.get("authority_url") or authority.get("url") or "")
        if not authority_url.startswith("https://"):
            issues.append("production_authority_url_must_be_https")

    pubkeys = [str(pk).strip().lower() for pk in (authority.get("trusted_authority_pubkeys") or [])]
    if not pubkeys:
        issues.append("missing_trusted_authority_pubkeys")
    elif any(pk in PLACEHOLDER_AUTHORITY_PUBKEYS or pk.startswith("replace_with") for pk in pubkeys):
        if allow_placeholder_authority:
            warnings.append("placeholder_trusted_authority_pubkey")
        else:
            issues.append("placeholder_trusted_authority_pubkey")

    issues.extend(_walk_secret_keys(bundle))
    issues.extend(_validate_relay_recipient_pubkeys(bundle))
    # Legacy read-only node-operator bundles from the pre-observer schema did not
    # include an observer section. Keep those verifiable for authority migration
    # tests and archival compatibility, while still requiring all modern bundles
    # with an observer section to fail closed on unsafe runtime flags.
    if isinstance(bundle.get("observer"), dict) or not ("authority" not in bundle and isinstance(bundle.get("oracle"), dict)):
        issues.extend(_validate_observer_posture(bundle))

    if manifest is not None:
        comparisons = {
            "chain_id": (chain.get("chain_id"), manifest.get("chain_id")),
            "genesis_hash": (chain.get("genesis_hash"), manifest.get("genesis_hash")),
            "genesis_state_root": (chain.get("genesis_state_root"), manifest.get("genesis_state_root")),
            "tx_index_hash": (chain.get("tx_index_hash"), manifest.get("tx_index_hash")),
            "schema_version": (str(chain.get("schema_version") or ""), str(manifest.get("schema_version") or "")),
            "protocol_profile_hash": (chain.get("protocol_profile_hash"), manifest.get("protocol_profile_hash")),
        }
        for name, (local, expected) in comparisons.items():
            if str(local or "").strip().lower() != str(expected or "").strip().lower():
                issues.append(f"manifest_{name}_mismatch")

    return {
        "ok": not issues,
        "issues": issues,
        "warnings": warnings,
        "chain_id": chain.get("chain_id"),
        "genesis_hash": chain.get("genesis_hash"),
        "tx_index_hash": chain.get("tx_index_hash"),
        "protocol_profile_hash": chain.get("protocol_profile_hash"),
        "authority_profile": authority.get("profile"),
        "authority_url": authority.get("authority_url") or authority.get("url"),
        "trusted_authority_pubkeys_count": len(pubkeys),
        "relay_recipient_pubkeys_count": len(_relay_recipient_pubkeys(bundle)),
        "legacy_authority_section_used": "authority" not in bundle and isinstance(bundle.get("oracle"), dict),
    }


def _shell_env(bundle: Json) -> str:
    chain = _chain(bundle)
    authority = _authority(bundle)
    observer = _observer(bundle)
    pubkeys = ",".join(str(pk).strip() for pk in (authority.get("trusted_authority_pubkeys") or []) if str(pk).strip())
    relay_recipient_pubkeys = json.dumps(_relay_recipient_pubkeys(bundle), separators=(",", ":"), sort_keys=True)
    lifecycle = str(observer.get("node_lifecycle_state") or "observer_onboarding").strip()
    if lifecycle not in SAFE_OBSERVER_LIFECYCLE_STATES:
        lifecycle = "observer_onboarding"
    env = {
        "WEALL_MODE": "prod" if str(bundle.get("profile") or "").lower() in {"prod", "production", "production_service"} else str(bundle.get("profile") or ""),
        "WEALL_CHAIN_ID": str(chain.get("chain_id") or ""),
        "WEALL_EXPECTED_CHAIN_ID": str(chain.get("chain_id") or ""),
        "WEALL_EXPECTED_GENESIS_HASH": str(chain.get("genesis_hash") or ""),
        "WEALL_EXPECTED_TX_INDEX_HASH": str(chain.get("tx_index_hash") or ""),
        "WEALL_EXPECTED_PROTOCOL_PROFILE_HASH": str(chain.get("protocol_profile_hash") or ""),
        "WEALL_CHAIN_AUTHORITY_URL": str(authority.get("authority_url") or authority.get("url") or ""),
        "WEALL_AUTHORITY_PUBKEYS": pubkeys,
        "WEALL_AUTHORITY_SNAPSHOT_MAX_AGE_MS": str(authority.get("authority_snapshot_max_age_ms") or "120000"),
        "WEALL_MIN_AUTHORITY_HEIGHT": str(authority.get("min_authority_height") or "0"),
        "WEALL_AUTHORITY_PROFILE": str(authority.get("profile") or "production"),
        "WEALL_GENESIS_API_BASE": str(observer.get("genesis_api_base") or ""),
        "WEALL_NET_RELAY_URLS": ",".join(str(url).strip() for url in (observer.get("relay_urls") or []) if str(url).strip()),
        "WEALL_NET_RELAY_RECIPIENT_PUBKEYS": relay_recipient_pubkeys if _relay_recipient_pubkeys(bundle) else "",
        # Observer posture is hard-coded here after validation.  The verifier must
        # never convert bundle-supplied authority toggles into shell exports.
        "WEALL_NODE_LIFECYCLE_STATE": lifecycle,
        "WEALL_SERVICE_ROLES": "",
        "WEALL_OBSERVER_MODE": "1",
        "WEALL_VALIDATOR_SIGNING_ENABLED": "0",
        "WEALL_BFT_ENABLED": "0",
        "WEALL_HELPER_MODE_ENABLED": "0",
        "WEALL_BLOCK_LOOP_AUTOSTART": "0",
    }
    force_empty = {"WEALL_SERVICE_ROLES"}
    lines = []
    for key, value in env.items():
        if value or key in force_empty:
            lines.append(f"export {key}={shlex.quote(value)}")
    return "\n".join(lines) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description="Verify a public WeAll node-operator onboarding bundle.")
    parser.add_argument("--bundle", required=True)
    parser.add_argument("--manifest", default="")
    parser.add_argument("--allow-placeholder-authority", action="store_true")
    parser.add_argument("--emit-shell-env", action="store_true")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()

    try:
        bundle = _load_json(Path(args.bundle))
        manifest = _load_json(Path(args.manifest)) if args.manifest else None
        result = _validate(bundle, manifest, allow_placeholder_authority=bool(args.allow_placeholder_authority))
    except Exception as exc:
        bundle = {}
        result = {"ok": False, "issues": [str(exc)], "warnings": []}

    if args.emit_shell_env:
        if not result.get("ok"):
            print(_json_dumps(result), file=sys.stderr)
            return 1
        print(_shell_env(bundle), end="")
        return 0

    if args.json:
        print(_json_dumps(result))
    else:
        if result.get("ok"):
            print("OK: node-operator onboarding bundle verified")
            for warning in result.get("warnings") or []:
                print(f"WARN: {warning}", file=sys.stderr)
        else:
            print("ERROR: node-operator onboarding bundle failed verification", file=sys.stderr)
            for issue in result.get("issues") or []:
                print(f"- {issue}", file=sys.stderr)
    return 0 if result.get("ok") else 1


if __name__ == "__main__":
    raise SystemExit(main())
