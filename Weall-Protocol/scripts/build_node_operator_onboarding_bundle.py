#!/usr/bin/env python3
"""Build a public node-operator onboarding bundle.

The bundle is safe to hand to a new WeAll node operator. It contains public
chain/oracle anchors only. It intentionally does not contain SMTP passwords, oracle private keys, authority-signer keys, or node private key material.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]

Json = dict[str, Any]

PROHIBITED_SECRET_KEYS = [
    "WEALL_SMTP_PASSWORD",
    "WEALL_EMAIL_ORACLE_PRIVATE_KEY",
    "WEALL_EMAIL_ORACLE_PRIVATE_KEY_FILE",
    "WEALL_NODE_PRIVKEY",
    "WEALL_NODE_PRIVKEY_FILE",
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


def _public_authority_pubkeys(manifest: Json, override: str) -> list[str]:
    values = _split_csv(override)
    if values:
        return values
    raw = manifest.get("trusted_authority_pubkeys") or []
    if isinstance(raw, list):
        return [str(item).strip() for item in raw if str(item).strip()]
    return []


def _build(args: argparse.Namespace) -> Json:
    manifest_path = Path(args.manifest).resolve()
    manifest = _load_json(manifest_path)
    oracle_profile = str(args.oracle_profile or manifest.get("oracle", {}).get("expected_profile") or args.profile).strip()
    authority_pubkeys = _public_authority_pubkeys(manifest, args.authority_pubkeys)

    generated_at_ms = int(args.generated_at_ms) if args.generated_at_ms else int(time.time() * 1000)
    bundle: Json = {
        "type": "weall_node_operator_onboarding_bundle",
        "version": 1,
        "profile": str(args.profile or manifest.get("mode") or "production").strip(),
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
        "oracle": {
            "profile": oracle_profile,
            "oracle_url": str(args.oracle_url or os.environ.get("WEALL_POH_EMAIL_ORACLE_URL") or os.environ.get("WEALL_EMAIL_ORACLE_URL") or "").rstrip("/"),
            "authority_url": str(args.authority_url or os.environ.get("WEALL_CHAIN_AUTHORITY_URL") or os.environ.get("WEALL_API_BASE") or "").rstrip("/"),
            "trusted_authority_pubkeys": authority_pubkeys,
            "min_authority_height": int(args.min_authority_height),
            "authority_snapshot_max_age_ms": int(args.authority_snapshot_max_age_ms),
        },
        "operator_requirements": {
            "minimum_poh_tier": 3,
            "requires_active_node_operator": True,
            "requires_positive_reputation": True,
            "requires_account_unlocked": True,
            "requires_account_not_banned": True,
            "requires_active_registered_node_key": True,
        },
        "secret_boundary": {
            "bundle_must_not_contain_secrets": True,
            "node_operator_must_not_have_oracle_service_secrets": True,
            "prohibited_environment_variables": PROHIBITED_SECRET_KEYS,
            "node_operator_uses": [
                "WEALL_ORACLE_OPERATOR_ACCOUNT or WEALL_VALIDATOR_ACCOUNT",
                "WEALL_NODE_PUBKEY",
                "WEALL_NODE_PRIVKEY_FILE or local signing key storage",
            ],
            "poh_email_oracle_operator_keeps_private": [
                "WEALL_SMTP_PASSWORD",
                "WEALL_EMAIL_ORACLE_PRIVATE_KEY",
                "WEALL_EMAIL_ORACLE_PRIVATE_KEY_FILE",
            ],
            "authority_snapshot_signer_keeps_private": [
                "WEALL_ORACLE_AUTHORITY_SIGNER_PRIVKEY",
            ],
        },
        "recommended_commands": {
            "verify_bundle": "python3 scripts/verify_node_operator_onboarding_bundle.py --bundle <bundle.json> --manifest configs/chains/weall-genesis.json --json",
            "node_preflight": "bash scripts/prod_node_operator_from_bundle_preflight.sh <bundle.json>",
            "oracle_start_dry_run": "bash scripts/prod_email_oracle_start.sh --dry-run --email user@example.com --account <account>",
        },
    }
    return bundle


def main() -> int:
    parser = argparse.ArgumentParser(description="Build a public WeAll node-operator onboarding bundle.")
    parser.add_argument("--manifest", default=str(ROOT / "configs" / "chains" / "weall-genesis.json"))
    parser.add_argument("--out", required=True)
    parser.add_argument("--profile", default="production")
    parser.add_argument("--oracle-profile", default="")
    parser.add_argument("--oracle-url", default="")
    parser.add_argument("--authority-url", default="")
    parser.add_argument("--authority-pubkeys", default="")
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
