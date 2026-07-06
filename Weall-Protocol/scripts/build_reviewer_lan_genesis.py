#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.mldsa import MLDSA65PrivateKey

from weall.runtime.state_hash import compute_state_root


ROOT = Path(__file__).resolve().parents[1]

DEFAULT_BASE_LEDGER = ROOT / "configs" / "genesis.ledger.prod.json"
DEFAULT_BASE_MANIFEST = ROOT / "configs" / "chains" / "weall-genesis.json"

OLD_ACCOUNT = "@errol-genesis"
OLD_CHAIN_ID = "weall-prod"
OLD_PUBKEY = "c195d59d38ecf84b9baa227aff88960759afb72d2150f6e27a3187d0a3ae08be"


def _read_json(path: Path) -> dict[str, Any]:
    obj = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(obj, dict):
        raise RuntimeError(f"JSON root must be object: {path}")
    return obj


def _write_json(path: Path, obj: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(obj, sort_keys=True, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )


def _replace_string(value: str, *, account: str, chain_id: str, pubkey: str) -> str:
    return (
        value.replace(OLD_ACCOUNT, account)
        .replace(OLD_CHAIN_ID, chain_id)
        .replace(OLD_PUBKEY, pubkey)
        .replace("production_genesis_manifest", "reviewer_disposable_genesis")
        .replace("production_genesis", "reviewer_disposable_genesis")
    )


def _replace_recursive(value: Any, *, account: str, chain_id: str, pubkey: str) -> Any:
    if isinstance(value, dict):
        out: dict[str, Any] = {}
        for key, item in value.items():
            key2 = _replace_string(str(key), account=account, chain_id=chain_id, pubkey=pubkey)
            out[key2] = _replace_recursive(item, account=account, chain_id=chain_id, pubkey=pubkey)
        return out
    if isinstance(value, list):
        return [_replace_recursive(item, account=account, chain_id=chain_id, pubkey=pubkey) for item in value]
    if isinstance(value, str):
        return _replace_string(value, account=account, chain_id=chain_id, pubkey=pubkey)
    return value


def _new_keypair() -> tuple[str, str]:
    private = MLDSA65PrivateKey.generate()
    seed = private.private_bytes_raw()
    pub = private.public_key().public_bytes_raw()
    return seed.hex(), pub.hex()


def _canonical_hash(obj: dict[str, Any]) -> str:
    canon = json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(canon.encode("utf-8")).hexdigest()


def _ensure_reviewer_ledger(
    ledger: dict[str, Any],
    *,
    account: str,
    chain_id: str,
    pubkey: str,
) -> dict[str, Any]:
    ledger = dict(ledger)
    ledger["chain_id"] = chain_id
    ledger["height"] = 0
    ledger["tip"] = ""
    ledger["blocks"] = {}
    ledger["finalized"] = False

    accounts = ledger.setdefault("accounts", {})
    if not isinstance(accounts, dict):
        raise RuntimeError("ledger.accounts must be object")
    acct = accounts.get(account)
    if not isinstance(acct, dict):
        raise RuntimeError(f"reviewer account missing after rewrite: {account}")

    acct["poh_tier"] = 2
    acct["reputation"] = "5.000"
    acct["reputation_milli"] = 5000
    acct["banned"] = False
    acct["locked"] = False
    acct["nonce"] = 0

    acct["keys"] = {
        "by_id": {
            f"k:{hashlib.sha256(pubkey.encode('utf-8')).hexdigest()[:16]}": {
                "key_type": "main",
                "label": "reviewer-disposable-bootstrap",
                "pubkey": pubkey,
                "revoked": False,
                "revoked_at": None,
            }
        }
    }
    acct["devices"] = {
        "by_id": {
            "node:reviewer-genesis": {
                "active": True,
                "device_type": "node",
                "label": "reviewer_disposable_node",
                "pubkey": pubkey,
                "revoked": False,
            }
        }
    }

    params = ledger.setdefault("params", {})
    if not isinstance(params, dict):
        params = {}
        ledger["params"] = params
    params["public_mainnet_enabled"] = False
    params["reviewer_rehearsal_disposable_chain"] = True
    params["bootstrap_founder_account"] = account
    params["bootstrap_allowlist"] = {
        account: {
            "pubkey": pubkey,
            "source": "reviewer_disposable_genesis",
        }
    }

    roles = ledger.setdefault("roles", {})
    if not isinstance(roles, dict):
        roles = {}
        ledger["roles"] = roles

    roles["node_operators"] = {
        "active_set": [account],
        "by_id": {
            account: {
                "activated_at_nonce": 0,
                "active": True,
                "enrolled": True,
                "enrolled_at_nonce": 0,
                "responsibilities": {
                    "validator": {
                        "active": True,
                        "bft_pubkey": pubkey,
                        "chain_id": chain_id,
                        "manifest_hash": "reviewer_disposable_genesis",
                        "opted_in": True,
                        "protocol_version": "2026.03-prod.6",
                        "readiness_expires_height": 0,
                        "readiness_receipt_hash": "reviewer_disposable_validator_ready",
                        "readiness_status": "ready",
                        "reputation_required_milli": 5000,
                        "runtime_profile_hash": "reviewer_disposable_genesis",
                        "schema_version": "1",
                        "tx_index_hash": "reviewer_disposable_genesis",
                    }
                },
                "source": "reviewer_disposable_genesis",
            }
        },
    }
    roles["validators"] = {
        "active_set": [account],
        "by_id": {
            account: {
                "active": True,
                "enrolled": True,
                "source": "reviewer_disposable_genesis",
            }
        },
    }

    consensus = ledger.setdefault("consensus", {})
    if not isinstance(consensus, dict):
        consensus = {}
        ledger["consensus"] = consensus
    consensus["validators"] = {
        "registry": {
            account: {
                "account_id": account,
                "pubkey": pubkey,
                "source": "reviewer_disposable_genesis",
                "status": "active",
            }
        }
    }

    ledger["validators"] = {
        "registry": {
            account: {
                "account_id": account,
                "pubkey": pubkey,
                "source": "reviewer_disposable_genesis",
                "status": "active",
            }
        }
    }

    meta = ledger.setdefault("meta", {})
    if not isinstance(meta, dict):
        meta = {}
        ledger["meta"] = meta
    meta["reviewer_rehearsal_disposable_chain"] = True
    meta["reviewer_rehearsal_account"] = account
    meta["reviewer_rehearsal_pubkey"] = pubkey
    meta["reviewer_rehearsal_truth_boundary"] = (
        "Disposable reviewer rehearsal chain only; not canonical production Genesis."
    )

    return ledger


def _build_manifest(
    base: dict[str, Any],
    *,
    chain_id: str,
    pubkey: str,
    genesis_hash: str,
    state_root: str,
) -> dict[str, Any]:
    manifest = dict(base)
    manifest = _replace_recursive(
        manifest,
        account="@reviewer-genesis",
        chain_id=chain_id,
        pubkey=pubkey,
    )
    manifest["chain_id"] = chain_id
    manifest["name"] = "WeAll Reviewer LAN Disposable Chain"
    manifest["notes"] = (
        "Disposable reviewer rehearsal chain. Generated locally for LAN review only. "
        "Not canonical production Genesis and not public mainnet."
    )
    manifest["trusted_authority_pubkeys"] = [pubkey]
    manifest["genesis_hash"] = genesis_hash
    manifest["genesis_state_root"] = state_root
    manifest["mode"] = "prod"
    manifest["profile"] = "production_service"

    authority = manifest.setdefault("authority", {})
    if isinstance(authority, dict):
        authority["expected_profile"] = "production"
        authority["authority_snapshot_required"] = True
        authority["signed_snapshot_required"] = True

    return manifest


def _write_env(path: Path, values: dict[str, str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    lines = [
        "# Generated by scripts/build_reviewer_lan_genesis.py",
        "# Local-only reviewer Genesis environment. Do not commit this file.",
        "",
    ]
    for key in sorted(values):
        value = values[key].replace("'", "'\"'\"'")
        lines.append(f"export {key}='{value}'")
    lines.append("")
    path.write_text("\n".join(lines), encoding="utf-8")
    path.chmod(0o600)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Build a disposable reviewer LAN Genesis ledger/manifest/keypair."
    )
    parser.add_argument("--out-dir", default="/tmp/weall-reviewer-lan-genesis")
    parser.add_argument("--base-ledger", default=str(DEFAULT_BASE_LEDGER))
    parser.add_argument("--base-manifest", default=str(DEFAULT_BASE_MANIFEST))
    parser.add_argument("--chain-id", default="weall-reviewer-lan")
    parser.add_argument("--account", default="@reviewer-genesis")
    parser.add_argument("--force", action="store_true")
    args = parser.parse_args()

    out_dir = Path(args.out_dir).expanduser().resolve()
    ledger_path = out_dir / "reviewer-genesis.ledger.json"
    manifest_path = out_dir / "reviewer-chain-manifest.json"
    env_path = out_dir / "reviewer-genesis.env"
    private_key_path = out_dir / "reviewer-genesis.private-key.hex"

    if out_dir.exists() and any(out_dir.iterdir()) and not args.force:
        raise SystemExit(f"output directory is not empty; use --force: {out_dir}")

    out_dir.mkdir(parents=True, exist_ok=True)

    privkey, pubkey = _new_keypair()

    base_ledger = _read_json(Path(args.base_ledger))
    rewritten = _replace_recursive(
        base_ledger,
        account=args.account,
        chain_id=args.chain_id,
        pubkey=pubkey,
    )
    if not isinstance(rewritten, dict):
        raise RuntimeError("rewritten ledger root was not object")
    ledger = _ensure_reviewer_ledger(
        rewritten,
        account=args.account,
        chain_id=args.chain_id,
        pubkey=pubkey,
    )

    genesis_hash = _canonical_hash(ledger)
    state_root = str(compute_state_root(ledger)).strip()

    base_manifest = _read_json(Path(args.base_manifest))
    manifest = _build_manifest(
        base_manifest,
        chain_id=args.chain_id,
        pubkey=pubkey,
        genesis_hash=genesis_hash,
        state_root=state_root,
    )

    _write_json(ledger_path, ledger)
    _write_json(manifest_path, manifest)
    private_key_path.write_text(privkey + "\n", encoding="utf-8")
    private_key_path.chmod(0o600)

    db_path = out_dir / "reviewer-genesis.sqlite3"
    aux_db_path = out_dir / "reviewer-genesis.aux.sqlite3"

    _write_env(
        env_path,
        {
            "WEALL_REVIEWER_DISPOSABLE_GENESIS": "1",
            "WEALL_REVIEWER_GENESIS_ACCOUNT": args.account,
            "WEALL_REVIEWER_GENESIS_PUBKEY": pubkey,
            "WEALL_MODE": "prod",
            "WEALL_CHAIN_ID": args.chain_id,
            "WEALL_CHAIN_MANIFEST_PATH": str(manifest_path),
            "WEALL_GENESIS_LEDGER_PATH": str(ledger_path),
            "WEALL_REQUIRE_PRODUCTION_GENESIS_LEDGER": "1",
            "WEALL_DB_PATH": str(db_path),
            "WEALL_AUX_DB_PATH": str(aux_db_path),
            "WEALL_NODE_LIFECYCLE_STATE": "production_service",
            "WEALL_OBSERVER_MODE": "0",
            "WEALL_BOUND_ACCOUNT": args.account,
            "WEALL_NODE_ID": args.account,
            "WEALL_NODE_PUBKEY": pubkey,
            "WEALL_NODE_PRIVKEY": privkey,
            "WEALL_SERVICE_ROLES": "",
            "WEALL_VALIDATOR_SIGNING_ENABLED": "0",
            "WEALL_BFT_ENABLED": "0",
            "WEALL_NET_ENABLED": "0",
            "WEALL_NET_LOOP_AUTOSTART": "0",
            "WEALL_BLOCK_LOOP_AUTOSTART": "1",
        },
    )

    summary = {
        "ok": True,
        "out_dir": str(out_dir),
        "account": args.account,
        "chain_id": args.chain_id,
        "pubkey": pubkey,
        "ledger_path": str(ledger_path),
        "manifest_path": str(manifest_path),
        "env_path": str(env_path),
        "private_key_path": str(private_key_path),
        "genesis_hash": genesis_hash,
        "genesis_state_root": state_root,
        "truth_boundary": (
            "Disposable reviewer rehearsal chain only; not canonical production Genesis."
        ),
    }
    print(json.dumps(summary, sort_keys=True, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
