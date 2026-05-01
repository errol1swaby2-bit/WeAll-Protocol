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


def _oracle(bundle: Json) -> Json:
    oracle = bundle.get("oracle")
    return oracle if isinstance(oracle, dict) else {}


def _validate(bundle: Json, manifest: Json | None, *, allow_placeholder_authority: bool) -> Json:
    issues: list[str] = []
    warnings: list[str] = []

    if bundle.get("type") != "weall_node_operator_onboarding_bundle":
        issues.append("bundle_wrong_type")
    if int(bundle.get("version") or 0) != 1:
        issues.append("bundle_wrong_version")

    chain = _chain(bundle)
    oracle = _oracle(bundle)
    required_chain = ["chain_id", "genesis_hash", "genesis_state_root", "tx_index_hash", "schema_version"]
    for key in required_chain:
        if not str(chain.get(key) or "").strip():
            issues.append(f"missing_chain_{key}")

    if str(bundle.get("profile") or "").lower() in {"prod", "production", "production_service"}:
        if str(oracle.get("profile") or "") != "production":
            issues.append("production_bundle_oracle_profile_not_production")
        if not str(oracle.get("oracle_url") or "").startswith("https://"):
            issues.append("production_oracle_url_must_be_https")
        if not str(oracle.get("authority_url") or "").startswith("https://"):
            issues.append("production_authority_url_must_be_https")

    pubkeys = [str(pk).strip().lower() for pk in (oracle.get("trusted_authority_pubkeys") or [])]
    if not pubkeys:
        issues.append("missing_trusted_authority_pubkeys")
    elif any(pk in PLACEHOLDER_AUTHORITY_PUBKEYS or pk.startswith("replace_with") for pk in pubkeys):
        if allow_placeholder_authority:
            warnings.append("placeholder_trusted_authority_pubkey")
        else:
            issues.append("placeholder_trusted_authority_pubkey")

    issues.extend(_walk_secret_keys(bundle))

    if manifest is not None:
        comparisons = {
            "chain_id": (chain.get("chain_id"), manifest.get("chain_id")),
            "genesis_hash": (chain.get("genesis_hash"), manifest.get("genesis_hash")),
            "genesis_state_root": (chain.get("genesis_state_root"), manifest.get("genesis_state_root")),
            "tx_index_hash": (chain.get("tx_index_hash"), manifest.get("tx_index_hash")),
            "schema_version": (str(chain.get("schema_version") or ""), str(manifest.get("schema_version") or "")),
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
        "oracle_profile": oracle.get("profile"),
        "oracle_url": oracle.get("oracle_url"),
        "authority_url": oracle.get("authority_url"),
        "trusted_authority_pubkeys_count": len(pubkeys),
    }


def _shell_env(bundle: Json) -> str:
    chain = _chain(bundle)
    oracle = _oracle(bundle)
    pubkeys = ",".join(str(pk).strip() for pk in (oracle.get("trusted_authority_pubkeys") or []) if str(pk).strip())
    env = {
        "WEALL_MODE": "prod" if str(bundle.get("profile") or "").lower() in {"prod", "production", "production_service"} else str(bundle.get("profile") or ""),
        "WEALL_CHAIN_ID": str(chain.get("chain_id") or ""),
        "WEALL_EXPECTED_CHAIN_ID": str(chain.get("chain_id") or ""),
        "WEALL_EXPECTED_GENESIS_HASH": str(chain.get("genesis_hash") or ""),
        "WEALL_EXPECTED_TX_INDEX_HASH": str(chain.get("tx_index_hash") or ""),
        "WEALL_CHAIN_AUTHORITY_URL": str(oracle.get("authority_url") or ""),
        "WEALL_ORACLE_AUTHORITY_PUBKEYS": pubkeys,
        "WEALL_AUTHORITY_SNAPSHOT_MAX_AGE_MS": str(oracle.get("authority_snapshot_max_age_ms") or "120000"),
        "WEALL_MIN_AUTHORITY_HEIGHT": str(oracle.get("min_authority_height") or "0"),
        "WEALL_ORACLE_PROFILE": str(oracle.get("profile") or "production"),
    }
    lines = []
    for key, value in env.items():
        if value:
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
