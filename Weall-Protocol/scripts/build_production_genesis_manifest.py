#!/usr/bin/env python3
"""Build a pinned production genesis ledger and chain manifest.

This is a ceremony helper, not a key generator.  It requires the operator to
provide public keys explicitly and refuses placeholder values.  The outputs are
safe to commit/share only after the operator has verified the public keys and
kept private keys out of the repository.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
import time
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
Json = dict[str, Any]
HEX64 = re.compile(r"^[0-9a-fA-F]{64}$")
SECONDS_PER_DAY = 24 * 60 * 60
DEFAULT_ECON_UNLOCK_DAYS = 90
DEFAULT_BOOTSTRAP_EXPIRES_HEIGHT = 1008


def _canon(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _pretty(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, indent=2) + "\n"


def _sha256(data: bytes | str) -> str:
    if isinstance(data, str):
        data = data.encode("utf-8")
    return hashlib.sha256(data).hexdigest()


def _file_hash(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _nonempty(value: str, name: str) -> str:
    text = str(value or "").strip()
    if not text:
        raise SystemExit(f"missing_required:{name}")
    lowered = text.lower()
    if lowered.startswith(("replace", "put_", "put-", "todo", "tbd", "pending")):
        raise SystemExit(f"placeholder_value:{name}")
    return text


def _hex64(value: str, name: str) -> str:
    text = _nonempty(value, name).lower()
    if not HEX64.match(text):
        raise SystemExit(f"invalid_hex64:{name}")
    return text


def _load_profile_hash() -> str:
    try:
        from weall.runtime.protocol_profile import PRODUCTION_CONSENSUS_PROFILE

        return str(PRODUCTION_CONSENSUS_PROFILE.profile_hash())
    except Exception as exc:  # pragma: no cover - defensive ceremony error path
        raise SystemExit(f"profile_hash_unavailable:{exc}") from exc


def _compute_state_root(state: Json) -> str:
    try:
        from weall.runtime.state_hash import compute_state_root

        return compute_state_root(state)
    except Exception:
        return _sha256(_canon(state))


def _build_genesis(
    *,
    chain_id: str,
    founding_account: str,
    founding_pubkey: str,
    genesis_time: int,
    econ_unlock_days: int,
    bootstrap_expires_height: int,
) -> Json:
    unlock_time = int(genesis_time) + int(econ_unlock_days) * SECONDS_PER_DAY
    return {
        "chain_id": chain_id,
        "height": 0,
        "tip": "",
        "time": int(genesis_time),
        "last_block_ts_ms": 0,
        "accounts": {
            "SYSTEM": {
                "nonce": 0,
                "poh_tier": 0,
                "banned": False,
                "locked": False,
                "balance": 0,
                "reputation": 0.0,
                "keys": [],
            },
            founding_account: {
                "nonce": 0,
                "poh_tier": 2,
                "banned": False,
                "locked": False,
                "balance": 0,
                "reputation": 0.0,
                "keys": {
                    founding_pubkey: {
                        "active": True,
                        "label": "bootstrap",
                    }
                },
                "devices": {
                    "node:founding": {
                        "active": True,
                        "device_type": "node",
                        "label": "node_bootstrap",
                        "pubkey": founding_pubkey,
                    }
                },
            },
        },
        "roles": {
            "validators": {
                "active_set": [founding_account],
            }
        },
        "finalized": False,
        "economics": {},
        "params": {
            "economics_enabled": False,
            "genesis_time": int(genesis_time),
            "economic_unlock_time": int(unlock_time),
            "bootstrap_allowlist": {
                founding_account: {
                    "pubkey": founding_pubkey,
                    "source": "genesis_bootstrap",
                }
            },
            "bootstrap_founder_account": founding_account,
            "bootstrap_expires_height": int(bootstrap_expires_height),
            "poh_bootstrap_max_height": 0,
            "poh_bootstrap_mode": "allowlist",
            "poh_bootstrap_auto_lock_rule": "active_validators>=BFT_MIN_VALIDATORS",
        },
        "blocks": {},
    }


def _build_manifest(
    *,
    chain_id: str,
    tx_index_hash: str,
    genesis_hash: str,
    genesis_state_root: str,
    protocol_profile_hash: str,
    authority_pubkey: str,
) -> Json:
    return {
        "authority": {
            "authority_snapshot_required": True,
            "expected_profile": "production",
            "signed_snapshot_required": True,
        },
        "authority_snapshot_version": 1,
        "chain_id": chain_id,
        "genesis_hash": genesis_hash,
        "genesis_state_root": genesis_state_root,
        "mode": "prod",
        "name": "WeAll Genesis Canonical Chain",
        "notes": "Pinned production chain identity. Private keys must never be committed or included in observer bundles.",
        "profile": "production_service",
        "protocol_profile_hash": protocol_profile_hash,
        "schema_version": "1",
        "trusted_authority_pubkeys": [authority_pubkey],
        "tx_index_hash": tx_index_hash,
        "version": 1,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Build pinned WeAll production genesis and chain manifest files.")
    parser.add_argument("--chain-id", default="weall-prod")
    parser.add_argument("--founding-account", required=True)
    parser.add_argument("--founding-pubkey", required=True, help="64 hex public key for founding account/node")
    parser.add_argument("--authority-pubkey", required=True, help="64 hex public key for signed authority snapshots")
    parser.add_argument("--tx-index", default=str(ROOT / "generated" / "tx_index.json"))
    parser.add_argument("--genesis-out", default=str(ROOT / "configs" / "genesis.ledger.prod.json"))
    parser.add_argument("--manifest-out", default=str(ROOT / "configs" / "chains" / "weall-genesis.json"))
    parser.add_argument("--genesis-time", type=int, default=0, help="Unix seconds. Defaults to current time.")
    parser.add_argument("--econ-unlock-days", type=int, default=DEFAULT_ECON_UNLOCK_DAYS)
    parser.add_argument("--bootstrap-expires-height", type=int, default=DEFAULT_BOOTSTRAP_EXPIRES_HEIGHT)
    args = parser.parse_args()

    chain_id = _nonempty(args.chain_id, "chain_id")
    founding_account = _nonempty(args.founding_account, "founding_account")
    founding_pubkey = _hex64(args.founding_pubkey, "founding_pubkey")
    authority_pubkey = _hex64(args.authority_pubkey, "authority_pubkey")
    tx_index_path = Path(args.tx_index).resolve()
    if not tx_index_path.is_file():
        raise SystemExit(f"tx_index_missing:{tx_index_path}")
    if int(args.econ_unlock_days) < DEFAULT_ECON_UNLOCK_DAYS:
        raise SystemExit("econ_unlock_days_must_be_at_least_90")
    if int(args.bootstrap_expires_height) <= 0:
        raise SystemExit("bootstrap_expires_height_must_be_positive")

    genesis_time = int(args.genesis_time or int(time.time()))
    genesis = _build_genesis(
        chain_id=chain_id,
        founding_account=founding_account,
        founding_pubkey=founding_pubkey,
        genesis_time=genesis_time,
        econ_unlock_days=int(args.econ_unlock_days),
        bootstrap_expires_height=int(args.bootstrap_expires_height),
    )
    state_root = _compute_state_root(genesis)
    genesis_hash = _sha256(_canon(genesis))
    manifest = _build_manifest(
        chain_id=chain_id,
        tx_index_hash=_file_hash(tx_index_path),
        genesis_hash=genesis_hash,
        genesis_state_root=state_root,
        protocol_profile_hash=_load_profile_hash(),
        authority_pubkey=authority_pubkey,
    )

    genesis_out = Path(args.genesis_out).resolve()
    manifest_out = Path(args.manifest_out).resolve()
    genesis_out.parent.mkdir(parents=True, exist_ok=True)
    manifest_out.parent.mkdir(parents=True, exist_ok=True)
    genesis_out.write_text(_pretty(genesis), encoding="utf-8")
    manifest_out.write_text(_pretty(manifest), encoding="utf-8")
    print(_pretty({
        "ok": True,
        "chain_id": chain_id,
        "genesis_out": str(genesis_out),
        "manifest_out": str(manifest_out),
        "genesis_hash": genesis_hash,
        "genesis_state_root": state_root,
        "tx_index_hash": manifest["tx_index_hash"],
        "protocol_profile_hash": manifest["protocol_profile_hash"],
        "economic_unlock_time": genesis["params"]["economic_unlock_time"],
        "bootstrap_auto_lock_rule": genesis["params"]["poh_bootstrap_auto_lock_rule"],
    }))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
