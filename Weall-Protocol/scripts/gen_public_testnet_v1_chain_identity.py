#!/usr/bin/env python3
from __future__ import annotations

"""Generate the pinned WeAll public testnet-v1 chain identity.

This script is deterministic and commits no private material.  It derives the
public testnet v1 genesis ledger from the same protocol/profile/constitution
commitments as the canonical genesis manifest, but pins a distinct resettable
chain_id and writes separate testnet artifacts.
"""

import argparse
import hashlib
import json
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

Json = dict[str, Any]
DEFAULT_CHAIN_ID = "weall-testnet-v1"
DEFAULT_NETWORK_ID = "weall-public-observer-testnet-v1"
DEFAULT_GENESIS_TIME = 0
DEFAULT_BOOTSTRAP_EXPIRES_HEIGHT = 1008
DEFAULT_ECON_UNLOCK_TIME = 7_776_000  # 90 days after genesis_time=0.


def _pretty(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, indent=2) + "\n"


def _canon(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _sha256(data: bytes | str) -> str:
    if isinstance(data, str):
        data = data.encode("utf-8")
    return hashlib.sha256(data).hexdigest()


def _file_hash(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _compute_state_root(state: Json) -> str:
    from weall.runtime.state_hash import compute_state_root

    return compute_state_root(state)


def _profile_hash() -> str:
    from weall.runtime.protocol_profile import PRODUCTION_CONSENSUS_PROFILE

    return str(PRODUCTION_CONSENSUS_PROFILE.profile_hash())


def _protocol_version() -> str:
    from weall.runtime.protocol_profile import PROTOCOL_VERSION

    return str(PROTOCOL_VERSION)


def _key_id(pubkey: str) -> str:
    return f"k:{_sha256(pubkey)[:16]}"


def _load_json(path: Path) -> Json:
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise SystemExit(f"json_root_not_object:{path}")
    return data


def _derive_founding_material(base_ledger: Json, base_manifest: Json) -> tuple[str, str, str]:
    account = str((base_ledger.get("params") or {}).get("bootstrap_founder_account") or "").strip()
    pubkey = ""
    if account:
        record = (base_ledger.get("accounts") or {}).get(account)
        if isinstance(record, dict):
            keys = ((record.get("keys") or {}).get("by_id") or {})
            if isinstance(keys, dict):
                for item in keys.values():
                    if isinstance(item, dict) and str(item.get("pubkey") or "").strip():
                        pubkey = str(item.get("pubkey") or "").strip().lower()
                        break
    if not account:
        account = "@errol-genesis"
    if not pubkey:
        pubkeys = base_manifest.get("trusted_authority_pubkeys") or []
        if isinstance(pubkeys, list) and pubkeys:
            pubkey = str(pubkeys[0] or "").strip().lower()
    authority_pubkeys = base_manifest.get("trusted_authority_pubkeys") or []
    authority = str(authority_pubkeys[0] if isinstance(authority_pubkeys, list) and authority_pubkeys else pubkey).strip().lower()
    if len(pubkey) != 64 or len(authority) != 64:
        raise SystemExit("missing_or_invalid_public_bootstrap_key")
    return account, pubkey, authority


def _build_testnet_genesis(*, chain_id: str, founding_account: str, founding_pubkey: str) -> Json:
    from weall.runtime.bootstrap_audit import record_bootstrap_tier2_grant

    founder_reputation_milli = 5000
    founding_key_id = _key_id(founding_pubkey)
    genesis: Json = {
        "chain_id": chain_id,
        "height": 0,
        "tip": "",
        "time": DEFAULT_GENESIS_TIME,
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
                "reputation": "5.000",
                "reputation_milli": founder_reputation_milli,
                "keys": {
                    "by_id": {
                        founding_key_id: {
                            "pubkey": founding_pubkey,
                            "key_type": "main",
                            "revoked": False,
                            "revoked_at": None,
                            "label": "bootstrap",
                        }
                    }
                },
                "devices": {
                    "by_id": {
                        "node:founding": {
                            "active": True,
                            "revoked": False,
                            "device_type": "node",
                            "label": "node_bootstrap",
                            "pubkey": founding_pubkey,
                        }
                    }
                },
                "recovery": {"config": None, "proposals": {}},
                "session_keys": {},
            },
        },
        "roles": {
            "node_operators": {
                "active_set": [founding_account],
                "by_id": {
                    founding_account: {
                        "enrolled": True,
                        "active": True,
                        "enrolled_at_nonce": 0,
                        "activated_at_nonce": 0,
                        "source": "public_testnet_v1_genesis_manifest",
                        "responsibilities": {
                            "validator": {
                                "opted_in": True,
                                "active": True,
                                "readiness_status": "ready",
                                "readiness_expires_height": 0,
                                "readiness_receipt_hash": "testnet_v1_genesis_bootstrap_validator_ready",
                                "reputation_required_milli": founder_reputation_milli,
                                "manifest_hash": "public_testnet_v1_genesis_manifest",
                                "tx_index_hash": "public_testnet_v1_genesis_manifest",
                                "runtime_profile_hash": "public_testnet_v1_genesis_manifest",
                                "chain_id": chain_id,
                                "schema_version": "1",
                                "protocol_version": _protocol_version(),
                                "bft_pubkey": founding_pubkey,
                            }
                        },
                    }
                },
            },
            "validators": {
                "active_set": [founding_account],
                "by_id": {
                    founding_account: {
                        "enrolled": True,
                        "active": True,
                        "source": "public_testnet_v1_genesis_manifest",
                    }
                },
            },
        },
        "consensus": {
            "validators": {
                "registry": {
                    founding_account: {
                        "account_id": founding_account,
                        "pubkey": founding_pubkey,
                        "status": "active",
                        "source": "public_testnet_v1_genesis_manifest",
                    }
                }
            }
        },
        "validators": {
            "registry": {
                founding_account: {
                    "account_id": founding_account,
                    "pubkey": founding_pubkey,
                    "status": "active",
                    "source": "public_testnet_v1_genesis_manifest",
                }
            }
        },
        "finalized": False,
        "economics": {},
        "params": {
            "economics_enabled": False,
            "genesis_time": DEFAULT_GENESIS_TIME,
            "economic_unlock_time": DEFAULT_ECON_UNLOCK_TIME,
            "bootstrap_allowlist": {
                founding_account: {
                    "pubkey": founding_pubkey,
                    "source": "testnet_v1_genesis_bootstrap",
                }
            },
            "bootstrap_founder_account": founding_account,
            "bootstrap_expires_height": DEFAULT_BOOTSTRAP_EXPIRES_HEIGHT,
            "poh_bootstrap_max_height": 0,
            "poh_bootstrap_mode": "allowlist",
            "poh_bootstrap_auto_lock_rule": "active_validators>=BFT_MIN_VALIDATORS",
            "poh_live_partial_panels_enabled": True,
            "poh_live_partial_until_height": DEFAULT_BOOTSTRAP_EXPIRES_HEIGHT,
            "poh": {
                "live_partial_panels_enabled": True,
                "live_partial_until_height": DEFAULT_BOOTSTRAP_EXPIRES_HEIGHT,
                "live_min_panel_after_bootstrap": 10,
            },
            "validator_candidate_lifecycle_gate_enabled": True,
            "validator_candidate_node_id_must_match_node_pubkey": True,
            "bft_signing_public_beta_gate_enabled": True,
            "public_mainnet_enabled": False,
            "public_testnet_v1": True,
            "resettable_testnet": True,
        },
        "blocks": {},
    }
    record_bootstrap_tier2_grant(
        genesis,
        account_id=founding_account,
        signer=founding_account,
        mode="public_testnet_v1_genesis",
        source="genesis_state",
        height=0,
        tx_type="TESTNET_V1_GENESIS_BOOTSTRAP_TIER2_GRANT",
        nonce=0,
        authority_path="public_testnet_v1_genesis_manifest",
        reason_code="testnet_v1_founder_live_bootstrap",
        expires_height=DEFAULT_BOOTSTRAP_EXPIRES_HEIGHT,
        pubkey=founding_pubkey,
    )
    return genesis


def _build_manifest(*, chain_id: str, base_manifest: Json, genesis_hash: str, genesis_state_root: str, tx_index_hash: str, protocol_profile_hash: str, authority_pubkey: str) -> Json:
    clock = dict(base_manifest.get("constitutional_clock") if isinstance(base_manifest.get("constitutional_clock"), dict) else {})
    if not clock:
        clock = {
            "allowed_clock_skew_ms": 2000,
            "block_time_derivation": "genesis_time_plus_height_times_interval",
            "empty_blocks_enabled": True,
            "enabled": True,
            "genesis_time_ms": 0,
            "no_fast_forward": True,
            "no_height_skip": True,
            "procedure_time_source": "finalized_block_height",
            "target_block_interval_ms": 20000,
        }
    clock["genesis_time_ms"] = 0
    return {
        "authority": {
            "authority_snapshot_required": True,
            "expected_profile": "public_testnet_v1",
            "signed_snapshot_required": True,
        },
        "authority_snapshot_version": int(base_manifest.get("authority_snapshot_version") or 1),
        "chain_id": chain_id,
        "constitution_document_path": str(base_manifest.get("constitution_document_path") or ""),
        "constitution_hash": str(base_manifest.get("constitution_hash") or ""),
        "constitution_traceability_hash": str(base_manifest.get("constitution_traceability_hash") or ""),
        "constitution_version": str(base_manifest.get("constitution_version") or ""),
        "constitutional_clock": clock,
        "genesis_hash": genesis_hash,
        "genesis_state_root": genesis_state_root,
        "genesis_time_ms": 0,
        "mode": "prod",
        "name": "WeAll Public Observer Testnet v1",
        "network_id": DEFAULT_NETWORK_ID,
        "notes": "Pinned resettable public observer testnet-v1 chain identity. Tokens, reputation, validator status, storage offers, and governance outcomes are resettable/non-economic unless a later governance/spec activation explicitly says otherwise. Private keys must never be committed or included in observer bundles.",
        "profile": "public_testnet_v1_service",
        "protocol_profile_hash": protocol_profile_hash,
        "resettable_testnet": True,
        "schema_version": "1",
        "trusted_authority_pubkeys": [authority_pubkey],
        "tx_index_hash": tx_index_hash,
        "version": 1,
    }


def _build_commitments(manifest: Json) -> Json:
    return {
        "network_id": DEFAULT_NETWORK_ID,
        "chain_id": manifest["chain_id"],
        "genesis_hash": manifest["genesis_hash"],
        "genesis_state_root": manifest["genesis_state_root"],
        "protocol_profile_hash": manifest["protocol_profile_hash"],
        "tx_index_hash": manifest["tx_index_hash"],
        "resettable_testnet": True,
        "economics_active": False,
        "source_manifest": "configs/chains/weall-testnet-v1.json",
        "source_genesis_ledger": "configs/genesis.ledger.testnet-v1.json",
        "notes": [
            "These commitments are the repo-pinned identity for the resettable public observer testnet v1.",
            "Seed registries must match all hash commitments before fresh observers accept discovery metadata.",
            "Discovery-level verification does not grant validator authority.",
        ],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate pinned WeAll public testnet-v1 chain identity artifacts.")
    parser.add_argument("--check", action="store_true", help="fail if generated artifacts differ from checked-in files")
    parser.add_argument("--chain-id", default=DEFAULT_CHAIN_ID)
    parser.add_argument("--base-manifest", default=str(ROOT / "configs" / "chains" / "weall-genesis.json"))
    parser.add_argument("--base-ledger", default=str(ROOT / "configs" / "genesis.ledger.prod.json"))
    parser.add_argument("--tx-index", default=str(ROOT / "generated" / "tx_index.json"))
    parser.add_argument("--genesis-out", default=str(ROOT / "configs" / "genesis.ledger.testnet-v1.json"))
    parser.add_argument("--manifest-out", default=str(ROOT / "configs" / "chains" / "weall-testnet-v1.json"))
    parser.add_argument("--commitments-out", default=str(ROOT / "configs" / "public_testnet_chain_commitments.json"))
    args = parser.parse_args()

    chain_id = str(args.chain_id or "").strip()
    if chain_id != DEFAULT_CHAIN_ID:
        raise SystemExit("public_testnet_v1_chain_id_must_be_weall-testnet-v1")
    base_manifest = _load_json(Path(args.base_manifest).resolve())
    base_ledger = _load_json(Path(args.base_ledger).resolve())
    tx_index_path = Path(args.tx_index).resolve()
    if not tx_index_path.is_file():
        raise SystemExit(f"tx_index_missing:{tx_index_path}")

    founding_account, founding_pubkey, authority_pubkey = _derive_founding_material(base_ledger, base_manifest)
    genesis = _build_testnet_genesis(chain_id=chain_id, founding_account=founding_account, founding_pubkey=founding_pubkey)
    genesis_state_root = _compute_state_root(genesis)
    genesis_hash = _sha256(_canon(genesis))
    manifest = _build_manifest(
        chain_id=chain_id,
        base_manifest=base_manifest,
        genesis_hash=genesis_hash,
        genesis_state_root=genesis_state_root,
        tx_index_hash=_file_hash(tx_index_path),
        protocol_profile_hash=_profile_hash(),
        authority_pubkey=authority_pubkey,
    )
    commitments = _build_commitments(manifest)

    outputs = {
        Path(args.genesis_out).resolve(): _pretty(genesis),
        Path(args.manifest_out).resolve(): _pretty(manifest),
        Path(args.commitments_out).resolve(): _pretty(commitments),
    }
    stale: list[str] = []
    for path, text in outputs.items():
        if args.check:
            if not path.is_file() or path.read_text(encoding="utf-8") != text:
                stale.append(str(path))
        else:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text, encoding="utf-8")
    if stale:
        raise SystemExit("public_testnet_v1_identity_stale:" + ",".join(stale))
    print(_pretty({
        "ok": True,
        "check": bool(args.check),
        "network_id": DEFAULT_NETWORK_ID,
        "chain_id": chain_id,
        "genesis_hash": genesis_hash,
        "genesis_state_root": genesis_state_root,
        "tx_index_hash": manifest["tx_index_hash"],
        "protocol_profile_hash": manifest["protocol_profile_hash"],
        "manifest_out": str(Path(args.manifest_out).resolve()),
        "genesis_out": str(Path(args.genesis_out).resolve()),
        "commitments_out": str(Path(args.commitments_out).resolve()),
    }))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
