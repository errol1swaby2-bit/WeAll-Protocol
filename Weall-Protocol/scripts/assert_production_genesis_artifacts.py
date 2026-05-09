#!/usr/bin/env python3
"""Fail-closed production genesis artifact verification.

This verifier is intentionally stricter than generic chain-manifest loading.
It checks the two launch-critical files together:

  - configs/chains/weall-genesis.json
  - configs/genesis.ledger.prod.json

It refuses stale tx_index hashes, placeholder values, inconsistent genesis
hash/state-root commitments, unsafe economics unlock windows, and bootstrap
artifacts that still look like templates.  It does not generate keys and it
never needs private keys; only public launch identifiers are inspected.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path
from typing import Any, Mapping

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

HEX64 = re.compile(r"^[0-9a-f]{64}$")
SECONDS_PER_DAY = 24 * 60 * 60
MIN_ECON_UNLOCK_DAYS = 90
PLACEHOLDER_PREFIXES = (
    "replace",
    "replace_",
    "replace-with",
    "put_",
    "put-",
    "todo",
    "tbd",
    "pending",
    "founding_",
)
PLACEHOLDER_SUBSTRINGS = (
    "replace_with",
    "put_founding",
    "placeholder",
    "example",
    "dummy",
)

Json = dict[str, Any]


def _canon(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _sha256(data: bytes | str) -> str:
    if isinstance(data, str):
        data = data.encode("utf-8")
    return hashlib.sha256(data).hexdigest()


def _load_json(path: Path) -> Json:
    obj = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(obj, dict):
        raise ValueError(f"json_root_not_object:{path}")
    return obj


def _is_placeholder(value: Any) -> bool:
    s = str(value or "").strip().lower()
    if not s:
        return True
    return s.startswith(PLACEHOLDER_PREFIXES) or any(part in s for part in PLACEHOLDER_SUBSTRINGS)


def _is_hex64(value: Any) -> bool:
    return bool(HEX64.match(str(value or "").strip().lower()))


def _file_hash(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _compute_state_root(state: Mapping[str, Any]) -> str:
    from weall.runtime.state_hash import compute_state_root

    return compute_state_root(dict(state))


def _expected_profile_hash() -> str:
    from weall.runtime.protocol_profile import PRODUCTION_CONSENSUS_PROFILE

    return str(PRODUCTION_CONSENSUS_PROFILE.profile_hash())


def _issue(issues: list[Json], code: str, detail: Any = None) -> None:
    row: Json = {"code": code}
    if detail is not None:
        row["detail"] = detail
    issues.append(row)


def _validate_manifest(manifest: Mapping[str, Any], *, tx_index_path: Path, issues: list[Json]) -> None:
    if str(manifest.get("mode") or "").strip().lower() != "prod":
        _issue(issues, "manifest_mode_not_prod", manifest.get("mode"))
    if str(manifest.get("profile") or "").strip().lower() != "production_service":
        _issue(issues, "manifest_profile_not_production_service", manifest.get("profile"))
    if _is_placeholder(manifest.get("chain_id")):
        _issue(issues, "manifest_chain_id_unpinned")
    if str(manifest.get("schema_version") or "").strip() != "1":
        _issue(issues, "manifest_schema_version_unexpected", manifest.get("schema_version"))

    tx_hash = str(manifest.get("tx_index_hash") or "").strip().lower()
    actual_tx_hash = _file_hash(tx_index_path) if tx_index_path.is_file() else ""
    if not _is_hex64(tx_hash):
        _issue(issues, "manifest_tx_index_hash_unpinned", tx_hash)
    elif actual_tx_hash and tx_hash != actual_tx_hash:
        _issue(
            issues,
            "manifest_tx_index_hash_mismatch",
            {"manifest": tx_hash, "actual": actual_tx_hash},
        )

    profile_hash = str(manifest.get("protocol_profile_hash") or "").strip().lower()
    expected_profile = _expected_profile_hash()
    if not _is_hex64(profile_hash):
        _issue(issues, "manifest_protocol_profile_hash_unpinned", profile_hash)
    elif profile_hash != expected_profile:
        _issue(
            issues,
            "manifest_protocol_profile_hash_mismatch",
            {"manifest": profile_hash, "actual": expected_profile},
        )

    authority_keys = manifest.get("trusted_authority_pubkeys")
    if not isinstance(authority_keys, list) or not authority_keys:
        _issue(issues, "manifest_trusted_authority_pubkeys_missing")
    else:
        for idx, key in enumerate(authority_keys):
            key_text = str(key or "").strip().lower()
            if _is_placeholder(key_text):
                _issue(issues, "manifest_trusted_authority_pubkey_unpinned", {"index": idx, "value": key_text})
            elif not _is_hex64(key_text):
                _issue(issues, "manifest_trusted_authority_pubkey_invalid", {"index": idx, "value": key_text})

    authority = manifest.get("authority") if isinstance(manifest.get("authority"), dict) else {}
    if authority.get("expected_profile") != "production":
        _issue(issues, "manifest_authority_expected_profile_not_production", authority.get("expected_profile"))
    if authority.get("signed_snapshot_required") is not True:
        _issue(issues, "manifest_signed_snapshot_not_required")
    if authority.get("authority_snapshot_required") is not True:
        _issue(issues, "manifest_authority_snapshot_not_required")


def _validate_genesis(genesis: Mapping[str, Any], *, manifest: Mapping[str, Any], issues: list[Json]) -> None:
    chain_id = str(genesis.get("chain_id") or "").strip()
    manifest_chain_id = str(manifest.get("chain_id") or "").strip()
    if _is_placeholder(chain_id):
        _issue(issues, "genesis_chain_id_unpinned")
    elif manifest_chain_id and chain_id != manifest_chain_id:
        _issue(issues, "genesis_chain_id_mismatch", {"genesis": chain_id, "manifest": manifest_chain_id})

    accounts = genesis.get("accounts") if isinstance(genesis.get("accounts"), dict) else {}
    if "SYSTEM" not in accounts:
        _issue(issues, "genesis_system_account_missing")

    params = genesis.get("params") if isinstance(genesis.get("params"), dict) else {}
    founding_account = str(params.get("bootstrap_founder_account") or "").strip()
    if _is_placeholder(founding_account):
        _issue(issues, "genesis_bootstrap_founder_account_unpinned", founding_account)
    elif founding_account not in accounts:
        _issue(issues, "genesis_bootstrap_founder_account_missing", founding_account)

    allowlist = params.get("bootstrap_allowlist") if isinstance(params.get("bootstrap_allowlist"), dict) else {}
    allow_rec = allowlist.get(founding_account) if founding_account else None
    if not isinstance(allow_rec, dict):
        _issue(issues, "genesis_bootstrap_allowlist_missing_founder", founding_account)
    else:
        allow_pubkey = str(allow_rec.get("pubkey") or "").strip().lower()
        if _is_placeholder(allow_pubkey):
            _issue(issues, "genesis_bootstrap_allowlist_pubkey_unpinned")
        elif not _is_hex64(allow_pubkey):
            _issue(issues, "genesis_bootstrap_allowlist_pubkey_invalid", allow_pubkey)

    founder = accounts.get(founding_account) if founding_account and isinstance(accounts.get(founding_account), dict) else {}
    keys = founder.get("keys") if isinstance(founder.get("keys"), dict) else {}
    if founding_account and not keys:
        _issue(issues, "genesis_founder_keys_missing", founding_account)
    for key in keys.keys():
        key_text = str(key or "").strip().lower()
        if _is_placeholder(key_text):
            _issue(issues, "genesis_founder_key_unpinned", key_text)
        elif not _is_hex64(key_text):
            _issue(issues, "genesis_founder_key_invalid", key_text)

    if int(params.get("genesis_time") or genesis.get("time") or 0) <= 0:
        _issue(issues, "genesis_time_unset")
    genesis_time = int(params.get("genesis_time") or genesis.get("time") or 0)
    unlock_time = int(params.get("economic_unlock_time") or 0)
    if unlock_time - genesis_time < MIN_ECON_UNLOCK_DAYS * SECONDS_PER_DAY:
        _issue(
            issues,
            "genesis_economic_unlock_less_than_90_days",
            {"genesis_time": genesis_time, "economic_unlock_time": unlock_time},
        )
    if params.get("economics_enabled") is not False:
        _issue(issues, "genesis_economics_enabled_not_false", params.get("economics_enabled"))
    if str(params.get("poh_bootstrap_mode") or "").strip() != "allowlist":
        _issue(issues, "genesis_poh_bootstrap_mode_not_allowlist", params.get("poh_bootstrap_mode"))
    if str(params.get("poh_bootstrap_auto_lock_rule") or "").strip() != "active_validators>=BFT_MIN_VALIDATORS":
        _issue(issues, "genesis_poh_bootstrap_auto_lock_rule_missing", params.get("poh_bootstrap_auto_lock_rule"))


def verify(*, manifest_path: Path, genesis_path: Path, tx_index_path: Path) -> Json:
    issues: list[Json] = []
    if not manifest_path.is_file():
        _issue(issues, "manifest_file_missing", str(manifest_path))
        manifest: Json = {}
    else:
        manifest = _load_json(manifest_path)
    if not genesis_path.is_file():
        _issue(issues, "genesis_file_missing", str(genesis_path))
        genesis: Json = {}
    else:
        genesis = _load_json(genesis_path)
    if not tx_index_path.is_file():
        _issue(issues, "tx_index_file_missing", str(tx_index_path))

    if manifest:
        _validate_manifest(manifest, tx_index_path=tx_index_path, issues=issues)
    if genesis and manifest:
        _validate_genesis(genesis, manifest=manifest, issues=issues)

    if genesis and manifest:
        genesis_hash = _sha256(_canon(genesis))
        state_root = _compute_state_root(genesis)
        manifest_genesis_hash = str(manifest.get("genesis_hash") or "").strip().lower()
        manifest_state_root = str(manifest.get("genesis_state_root") or "").strip().lower()
        if not _is_hex64(manifest_genesis_hash):
            _issue(issues, "manifest_genesis_hash_unpinned", manifest_genesis_hash)
        elif manifest_genesis_hash != genesis_hash:
            _issue(issues, "manifest_genesis_hash_mismatch", {"manifest": manifest_genesis_hash, "actual": genesis_hash})
        if not _is_hex64(manifest_state_root):
            _issue(issues, "manifest_genesis_state_root_unpinned", manifest_state_root)
        elif manifest_state_root != state_root:
            _issue(issues, "manifest_genesis_state_root_mismatch", {"manifest": manifest_state_root, "actual": state_root})
    else:
        genesis_hash = ""
        state_root = ""

    return {
        "ok": not issues,
        "manifest_path": str(manifest_path),
        "genesis_path": str(genesis_path),
        "tx_index_path": str(tx_index_path),
        "manifest_chain_id": str(manifest.get("chain_id") or "") if manifest else "",
        "genesis_chain_id": str(genesis.get("chain_id") or "") if genesis else "",
        "tx_index_hash": _file_hash(tx_index_path) if tx_index_path.is_file() else "",
        "genesis_hash": genesis_hash,
        "genesis_state_root": state_root,
        "issues": issues,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Verify launch-critical WeAll production genesis artifacts.")
    parser.add_argument("--manifest", default=str(ROOT / "configs" / "chains" / "weall-genesis.json"))
    parser.add_argument("--genesis", default=str(ROOT / "configs" / "genesis.ledger.prod.json"))
    parser.add_argument("--tx-index", default=str(ROOT / "generated" / "tx_index.json"))
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()

    report = verify(
        manifest_path=Path(args.manifest).resolve(),
        genesis_path=Path(args.genesis).resolve(),
        tx_index_path=Path(args.tx_index).resolve(),
    )
    print(json.dumps(report, sort_keys=True, indent=2))
    if not report["ok"]:
        return 2
    print("ok: production genesis artifacts are pinned, current, and mutually consistent")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
