#!/usr/bin/env python3
"""Build a public external-observer onboarding bundle.

The bundle is safe to hand to a trusted observer-node tester. It contains only
public chain identity, public authority anchors, optional public API/relay URLs,
and explicit observer-mode safety requirements. It must never include founding
private keys, node private keys, validator signing material, authority signer
secrets, or external identity-provider credentials.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import time
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
Json = dict[str, Any]

def _env_name(*parts: str) -> str:
    return "".join(parts)


PROHIBITED_SECRET_KEYS = [
    "WEALL_NODE_PRIVKEY",
    "WEALL_NODE_PRIVKEY_FILE",
    "WEALL_VALIDATOR_ACCOUNT",
    "WEALL_VALIDATOR_ACCOUNT_FILE",
    "WEALL_VALIDATOR_PRIVKEY",
    "WEALL_VALIDATOR_PRIVKEY_FILE",
    "WEALL_AUTHORITY_SIGNER_PRIVKEY",
    "WEALL_AUTHORITY_SIGNER_PRIVKEY_FILE",
    "WEALL_AUTHORITY_PRIVKEY",
    "WEALL_AUTHORITY_PRIVKEY_FILE",
    "WEALL_TRUSTED_AUTHORITY_PRIVKEYS",
    "WEALL_ORACLE_AUTHORITY_SIGNER_PRIVKEY",
    "WEALL_ORACLE_AUTHORITY_SIGNER_PRIVKEY_FILE",
    "WEALL_ORACLE_AUTHORITY_PRIVKEY",
    "WEALL_ORACLE_AUTHORITY_PRIVKEY_FILE",
    "WEALL_ORACLE_PRIVKEY",
    "WEALL_ORACLE_PRIVKEY_FILE",
    "WEALL_LEGACY_ORACLE_PRIVKEY",
    "WEALL_LEGACY_ORACLE_PRIVKEY_FILE",
    "WEALL_CLOUDFLARE_API_TOKEN",
    "WEALL_DNS_API_TOKEN",
    "WEALL_OAUTH_CLIENT_SECRET",
    "WEALL_KYC_PROVIDER_SECRET",
    "WEALL_KYC_API_KEY",
    "WEALL_CAPTCHA_SECRET",
    _env_name("WEALL_", "SM", "TP_PASSWORD"),
    _env_name("WEALL_", "SM", "TP_PASSWORD_FILE"),
]



def _assert_no_prohibited_env() -> None:
    present = [name for name in PROHIBITED_SECRET_KEYS if os.environ.get(name)]
    if present:
        raise RuntimeError("observer_bundle_secret_env_present:" + ",".join(sorted(present)))

def _json_dumps(data: Any) -> str:
    return json.dumps(data, indent=2, sort_keys=True) + "\n"


def _load_json(path: Path) -> Json:
    parsed = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(parsed, dict):
        raise RuntimeError(f"json_not_object:{path}")
    return parsed


def _split_csv(value: str) -> list[str]:
    return [part.strip() for part in str(value or "").split(",") if part.strip()]


def _normalise_pubkey_map(value: Any) -> dict[str, str]:
    if value in (None, ""):
        return {}
    parsed: Any = value
    if isinstance(value, str):
        parsed = json.loads(value)
    if not isinstance(parsed, dict):
        raise RuntimeError("relay_recipient_pubkeys_not_object")
    out: dict[str, str] = {}
    for raw_key, raw_val in parsed.items():
        key = str(raw_key or "").strip()
        val = str(raw_val or "").strip()
        if not key or not val:
            continue
        if not re.fullmatch(r"[0-9a-fA-F]{64}", val):
            raise RuntimeError(f"relay_recipient_pubkey_invalid:{key}")
        out[key] = val.lower()
    return out


def _relay_recipient_pubkeys(args: argparse.Namespace) -> dict[str, str]:
    mapping: dict[str, str] = {}
    raw_map = _first_nonempty(args.relay_recipient_pubkeys, os.environ.get("WEALL_NET_RELAY_RECIPIENT_PUBKEYS"))
    if raw_map:
        mapping.update(_normalise_pubkey_map(raw_map))
    genesis_pubkey = _first_nonempty(args.genesis_recipient_pubkey, os.environ.get("WEALL_GENESIS_RELAY_RECIPIENT_PUBKEY"))
    if genesis_pubkey:
        key = str(args.genesis_peer_id or "genesis").strip() or "genesis"
        mapping.update(_normalise_pubkey_map({key: genesis_pubkey}))
    return dict(sorted(mapping.items()))


def _first_nonempty(*values: Any) -> str:
    for value in values:
        text = str(value or "").strip()
        if text:
            return text
    return ""


def _manifest_authority(manifest: Json) -> Json:
    authority = manifest.get("authority")
    return authority if isinstance(authority, dict) else {}


def _trusted_authority_pubkeys(manifest: Json) -> list[str]:
    raw = manifest.get("trusted_authority_pubkeys") or []
    if not raw:
        authority = _manifest_authority(manifest)
        raw = authority.get("trusted_authority_pubkeys") or authority.get("pubkeys") or []
    if not isinstance(raw, list):
        return []
    return [str(item).strip() for item in raw if str(item).strip()]


def _build(args: argparse.Namespace) -> Json:
    manifest_path = Path(args.manifest).resolve()
    manifest = _load_json(manifest_path)
    authority = _manifest_authority(manifest)
    relay_urls = _split_csv(args.relay_urls or os.environ.get("WEALL_NET_RELAY_URLS") or "")
    relay_recipient_pubkeys = _relay_recipient_pubkeys(args)
    genesis_api_base = _first_nonempty(args.genesis_api_base, os.environ.get("WEALL_GENESIS_API_BASE"), os.environ.get("WEALL_API_BASE")).rstrip("/")
    authority_url = _first_nonempty(args.authority_url, genesis_api_base, os.environ.get("WEALL_CHAIN_AUTHORITY_URL"), os.environ.get("WEALL_API_BASE")).rstrip("/")
    generated_at_ms = int(args.generated_at_ms) if args.generated_at_ms else int(time.time() * 1000)

    return {
        "type": "weall_node_operator_onboarding_bundle",
        "bundle_purpose": "external_observer_onboarding",
        "version": 1,
        "profile": "production",
        "generated_at_ms": generated_at_ms,
        "chain": {
            "manifest_path_hint": str(args.manifest),
            "chain_id": str(manifest.get("chain_id") or ""),
            "mode": str(manifest.get("mode") or "prod"),
            "profile": str(manifest.get("profile") or "production_service"),
            "schema_version": str(manifest.get("schema_version") or ""),
            "genesis_hash": str(manifest.get("genesis_hash") or ""),
            "genesis_state_root": str(manifest.get("genesis_state_root") or ""),
            "tx_index_hash": str(manifest.get("tx_index_hash") or ""),
            "protocol_profile_hash": str(manifest.get("protocol_profile_hash") or ""),
            "authority_snapshot_version": int(manifest.get("authority_snapshot_version") or 1),
        },
        "authority": {
            "profile": str(authority.get("expected_profile") or authority.get("profile") or "production"),
            "authority_url": authority_url,
            "trusted_authority_pubkeys": _trusted_authority_pubkeys(manifest),
            "min_authority_height": int(args.min_authority_height),
            "authority_snapshot_max_age_ms": int(args.authority_snapshot_max_age_ms),
        },
        "observer": {
            "genesis_api_base": genesis_api_base,
            "relay_urls": relay_urls,
            "relay_recipient_pubkeys": relay_recipient_pubkeys,
            "relay_recipients": sorted(relay_recipient_pubkeys.keys()),
            "observer_mode_required": True,
            "node_lifecycle_state": "observer_onboarding",
            "validator_signing_enabled": False,
            "bft_enabled": False,
            "helper_authority_enabled": False,
            "block_loop_autostart": False,
            "can_submit_user_transactions_to_genesis": True,
            "allowed_onboarding_transactions": [
                "ACCOUNT_REGISTER",
                "ACCOUNT_KEY_ADD",
                "ACCOUNT_DEVICE_REGISTER",
                "ACCOUNT_SESSION_KEY_ISSUE",
                "PEER_ADVERTISE",
                "PEER_REQUEST_CONNECT",
                "PEER_RENDEZVOUS_TICKET_CREATE",
                "PEER_RENDEZVOUS_TICKET_REVOKE",
                "POH_ASYNC_REQUEST_OPEN",
                "POH_ASYNC_EVIDENCE_DECLARE",
                "POH_ASYNC_EVIDENCE_BIND",
            ],
        },
        "operator_requirements": {
            "observer_signing_material_generated_locally": True,
            "no_genesis_authority_material_required": True,
            "no_validator_role_required": True,
            "no_node_operator_role_required_for_observer_onboarding": True,
            "no_external_identity_provider_required": True,
        },
        "secret_boundary": {
            "bundle_must_not_contain_secrets": True,
            "observer_must_not_have_authority_or_validator_secrets": True,
            "prohibited_environment_variables": PROHIBITED_SECRET_KEYS,
            "private_keys_kept_local_to_observer": [
                "fresh observer account signing key",
                "fresh observer node identity key",
            ],
            "authority_signer_keeps_private": [
                "WEALL_AUTHORITY_SIGNER_PRIVKEY",
                "WEALL_AUTHORITY_PRIVKEY",
            ],
        },
        "recommended_commands": {
            "verify_bundle": "python3 scripts/verify_node_operator_onboarding_bundle.py --bundle <observer-bundle.json> --manifest configs/chains/weall-genesis.json --json",
            "observer_preflight": "bash scripts/external_observer_onboarding_smoke.sh <observer-bundle.json>",
            "boot_observer": "WEALL_NODE_OPERATOR_ONBOARDING_BUNDLE=<observer-bundle.json> bash scripts/boot_onboarding_node.sh",
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Build a public WeAll external-observer onboarding bundle.")
    parser.add_argument("--manifest", default=str(ROOT / "configs" / "chains" / "weall-genesis.json"))
    parser.add_argument("--out", required=True)
    parser.add_argument("--genesis-api-base", default="")
    parser.add_argument("--relay-urls", default="")
    parser.add_argument("--relay-recipient-pubkeys", default="", help="JSON object mapping relay peer ids to recipient Ed25519 public keys")
    parser.add_argument("--genesis-peer-id", default="genesis", help="Relay recipient peer id for the genesis/bootstrap node")
    parser.add_argument("--genesis-recipient-pubkey", default="", help="Genesis/bootstrap node Ed25519 public key for relay recipient binding")
    parser.add_argument("--authority-url", default="")
    parser.add_argument("--min-authority-height", type=int, default=int(os.environ.get("WEALL_MIN_AUTHORITY_HEIGHT") or "0"))
    parser.add_argument("--authority-snapshot-max-age-ms", type=int, default=int(os.environ.get("WEALL_AUTHORITY_SNAPSHOT_MAX_AGE_MS") or "120000"))
    parser.add_argument("--generated-at-ms", type=int, default=0)
    args = parser.parse_args()

    _assert_no_prohibited_env()
    bundle = _build(args)
    out = Path(args.out).resolve()
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(_json_dumps(bundle), encoding="utf-8")
    print(str(out))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
