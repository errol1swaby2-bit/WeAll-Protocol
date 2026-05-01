#!/usr/bin/env python3
"""Build a public node-operator onboarding bundle.

The bundle is safe to hand to a new WeAll node operator. It contains public
chain identity, public authority anchors, and operator preflight requirements.
It must not contain node private keys, authority signer keys, transport secrets,
or external identity-provider credentials.
"""
from __future__ import annotations

import argparse
import json
import os
import time
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
Json = dict[str, Any]

PROHIBITED_SECRET_KEYS = [
    "WEALL_NODE_PRIVKEY",
    "WEALL_NODE_PRIVKEY_FILE",
    "WEALL_AUTHORITY_SIGNER_PRIVKEY",
    "WEALL_AUTHORITY_PRIVKEY",
    "WEALL_ORACLE_AUTHORITY_SIGNER_PRIVKEY",
    "WEALL_ORACLE_AUTHORITY_PRIVKEY",
    "WEALL_TRUSTED_AUTHORITY_PRIVKEYS",
]


def _json_dumps(data: Any) -> str:
    return json.dumps(data, indent=2, sort_keys=True) + "\n"


def _split_csv(value: str) -> list[str]:
    return [part.strip() for part in str(value or "").split(",") if part.strip()]


def _load_json(path: Path) -> Json:
    parsed = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(parsed, dict):
        raise RuntimeError(f"json_not_object:{path}")
    return parsed


def _manifest_authority(manifest: Json) -> Json:
    authority = manifest.get("authority")
    if isinstance(authority, dict):
        return authority
    legacy_authority = manifest.get("oracle")
    if isinstance(legacy_authority, dict):
        return legacy_authority
    return {}


def _public_authority_pubkeys(manifest: Json, override: str) -> list[str]:
    values = _split_csv(override)
    if values:
        return values

    raw = manifest.get("trusted_authority_pubkeys") or []
    if not raw:
        authority = _manifest_authority(manifest)
        raw = authority.get("trusted_authority_pubkeys") or authority.get("pubkeys") or []

    if isinstance(raw, list):
        return [str(item).strip() for item in raw if str(item).strip()]
    return []


def _first_nonempty(*values: Any) -> str:
    for value in values:
        text = str(value or "").strip()
        if text:
            return text
    return ""


def _build(args: argparse.Namespace) -> Json:
    manifest_path = Path(args.manifest).resolve()
    manifest = _load_json(manifest_path)
    manifest_authority = _manifest_authority(manifest)

    authority_profile = _first_nonempty(
        args.authority_profile,
        args.oracle_profile,
        manifest_authority.get("expected_profile"),
        manifest_authority.get("profile"),
        args.profile,
    )
    authority_url = _first_nonempty(
        args.authority_url,
        args.oracle_url,
        os.environ.get("WEALL_CHAIN_AUTHORITY_URL"),
        os.environ.get("WEALL_API_BASE"),
    ).rstrip("/")
    authority_pubkeys = _public_authority_pubkeys(manifest, args.authority_pubkeys)

    generated_at_ms = int(args.generated_at_ms) if args.generated_at_ms else int(time.time() * 1000)
    return {
        "type": "weall_node_operator_onboarding_bundle",
        "version": 1,
        "profile": _first_nonempty(args.profile, manifest.get("mode"), "production"),
        "generated_at_ms": generated_at_ms,
        "chain": {
            "manifest_path_hint": str(args.manifest),
            "chain_id": str(manifest.get("chain_id") or ""),
            "mode": str(manifest.get("mode") or ""),
            "profile": str(manifest.get("profile") or ""),
            "schema_version": str(manifest.get("schema_version") or ""),
            "genesis_hash": str(manifest.get("genesis_hash") or ""),
            "genesis_state_root": str(manifest.get("genesis_state_root") or ""),
            "tx_index_hash": str(manifest.get("tx_index_hash") or ""),
            "protocol_profile_hash": str(manifest.get("protocol_profile_hash") or ""),
            "authority_snapshot_version": int(manifest.get("authority_snapshot_version") or 1),
        },
        "authority": {
            "profile": authority_profile,
            "authority_url": authority_url,
            "trusted_authority_pubkeys": authority_pubkeys,
            "min_authority_height": int(args.min_authority_height),
            "authority_snapshot_max_age_ms": int(args.authority_snapshot_max_age_ms),
        },
        "operator_requirements": {
            "minimum_poh_tier": 2,
            "requires_active_node_operator": True,
            "requires_positive_reputation": True,
            "requires_account_unlocked": True,
            "requires_account_not_banned": True,
            "requires_active_registered_node_key": True,
        },
        "secret_boundary": {
            "bundle_must_not_contain_secrets": True,
            "node_operator_must_not_have_external_identity_or_authority_secrets": True,
            "prohibited_environment_variables": PROHIBITED_SECRET_KEYS,
            "node_operator_uses": [
                "WEALL_BOOTSTRAP_OPERATOR_ACCOUNT or WEALL_VALIDATOR_ACCOUNT",
                "WEALL_NODE_PUBKEY",
                "WEALL_NODE_PRIVKEY_FILE or local signing key storage",
            ],
            "authority_signer_keeps_private": [
                "WEALL_AUTHORITY_SIGNER_PRIVKEY",
                "WEALL_AUTHORITY_PRIVKEY",
            ],
            "legacy_authority_signer_names_rejected_if_present": [
                "WEALL_ORACLE_AUTHORITY_SIGNER_PRIVKEY",
                "WEALL_ORACLE_AUTHORITY_PRIVKEY",
            ],
        },
        "recommended_commands": {
            "verify_bundle": "python3 scripts/verify_node_operator_onboarding_bundle.py --bundle <bundle.json> --manifest configs/chains/weall-genesis.json --json",
            "node_preflight": "bash scripts/prod_node_operator_from_bundle_preflight.sh <bundle.json>",
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Build a public WeAll node-operator onboarding bundle.")
    parser.add_argument("--manifest", default=str(ROOT / "configs" / "chains" / "weall-genesis.json"))
    parser.add_argument("--out", required=True)
    parser.add_argument("--profile", default="production")
    parser.add_argument("--authority-profile", default="")
    parser.add_argument("--authority-url", default="")
    parser.add_argument("--authority-pubkeys", default="")
    parser.add_argument("--oracle-profile", default="", help=argparse.SUPPRESS)
    parser.add_argument("--oracle-url", default="", help=argparse.SUPPRESS)
    parser.add_argument("--min-authority-height", type=int, default=int(os.environ.get("WEALL_MIN_AUTHORITY_HEIGHT") or "0"))
    parser.add_argument("--authority-snapshot-max-age-ms", type=int, default=int(os.environ.get("WEALL_AUTHORITY_SNAPSHOT_MAX_AGE_MS") or "120000"))
    parser.add_argument("--generated-at-ms", type=int, default=0)
    args = parser.parse_args()

    bundle = _build(args)
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(_json_dumps(bundle), encoding="utf-8")
    print(str(out))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
