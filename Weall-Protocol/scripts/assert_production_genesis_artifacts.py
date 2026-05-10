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




def _truthy(value: Any) -> bool:
    if isinstance(value, bool):
        return bool(value)
    if value is None:
        return False
    return str(value).strip().lower() in {"1", "true", "yes", "y", "on", "open", "enabled"}


_PROD_FORBIDDEN_CHAIN_PARAM_FLAGS = (
    "poh_bootstrap_open",
    "allow_case_scoped_juror_without_role",
    "poh_allow_case_scoped_juror_without_role",
    "bootstrap_allow_case_scoped_juror_without_role",
    "seeded_demo_review_fallback",
)


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

    poh = genesis.get("poh") if isinstance(genesis.get("poh"), dict) else {}
    grants = poh.get("bootstrap_grants") if isinstance(poh.get("bootstrap_grants"), dict) else {}
    grants_by_id = grants.get("by_id") if isinstance(grants.get("by_id"), dict) else {}
    grants_by_account = grants.get("by_account") if isinstance(grants.get("by_account"), dict) else {}
    founder_grant_ids = grants_by_account.get(founding_account) if founding_account else None
    if not isinstance(founder_grant_ids, list) or not founder_grant_ids:
        _issue(issues, "genesis_founder_bootstrap_grant_audit_missing", founding_account)
    else:
        for grant_id in founder_grant_ids:
            grant = grants_by_id.get(str(grant_id)) if isinstance(grants_by_id, dict) else None
            if not isinstance(grant, dict):
                _issue(issues, "genesis_founder_bootstrap_grant_audit_record_missing", grant_id)
                continue
            if grant.get("account_id") != founding_account:
                _issue(issues, "genesis_founder_bootstrap_grant_account_mismatch", grant)
            if grant.get("grant_type") != "poh_tier2_live_verified":
                _issue(issues, "genesis_founder_bootstrap_grant_type_unexpected", grant.get("grant_type"))
            if grant.get("auditable") is not True:
                _issue(issues, "genesis_founder_bootstrap_grant_not_auditable", grant_id)
            if grant.get("transitional") is not True:
                _issue(issues, "genesis_founder_bootstrap_grant_not_transitional", grant_id)
            if not isinstance(grant.get("grant_height"), int) or int(grant.get("grant_height") or 0) != 0:
                _issue(issues, "genesis_founder_bootstrap_grant_height_unexpected", grant.get("grant_height"))
            if not isinstance(grant.get("expires_height"), int) or int(grant.get("expires_height") or 0) <= int(grant.get("grant_height") or 0):
                _issue(issues, "genesis_founder_bootstrap_grant_expiry_missing", grant_id)
            if not str(grant.get("reason_code") or "").strip():
                _issue(issues, "genesis_founder_bootstrap_reason_missing", grant_id)
            if not str(grant.get("authority_path") or "").strip():
                _issue(issues, "genesis_founder_bootstrap_authority_path_missing", grant_id)
            if not str(grant.get("review_condition") or "").strip():
                _issue(issues, "genesis_founder_bootstrap_review_condition_missing", grant_id)
            if not str(grant.get("receipt_id") or "").startswith("poh_bootstrap_receipt:"):
                _issue(issues, "genesis_founder_bootstrap_receipt_missing", grant_id)
    if founding_account and founder:
        if not str(founder.get("poh_bootstrap_grant_id") or "").startswith("poh_bootstrap_grant:"):
            _issue(issues, "genesis_founder_account_bootstrap_grant_pointer_missing", founding_account)
        receipt_pointer = str(founder.get("poh_bootstrap_receipt_id") or "").strip()
        if not receipt_pointer.startswith("poh_bootstrap_receipt:"):
            _issue(issues, "genesis_founder_account_bootstrap_receipt_pointer_missing", founding_account)
        else:
            for grant_id in founder_grant_ids if isinstance(founder_grant_ids, list) else []:
                grant = grants_by_id.get(str(grant_id)) if isinstance(grants_by_id, dict) else None
                if isinstance(grant, dict) and str(grant.get("receipt_id") or "").strip() != receipt_pointer:
                    _issue(
                        issues,
                        "genesis_founder_account_bootstrap_receipt_pointer_mismatch",
                        {"account": founding_account, "grant_id": grant_id, "account_receipt": receipt_pointer, "grant_receipt": grant.get("receipt_id")},
                    )

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
    if str(params.get("poh_bootstrap_mode") or "").strip().lower() == "open":
        _issue(issues, "genesis_poh_bootstrap_open_forbidden_in_prod", params.get("poh_bootstrap_mode"))
    for flag in _PROD_FORBIDDEN_CHAIN_PARAM_FLAGS:
        if _truthy(params.get(flag)):
            _issue(issues, "genesis_forbidden_production_chain_param", {"param": flag, "value": params.get(flag)})
    if str(params.get("poh_bootstrap_auto_lock_rule") or "").strip() != "active_validators>=BFT_MIN_VALIDATORS":
        _issue(issues, "genesis_poh_bootstrap_auto_lock_rule_missing", params.get("poh_bootstrap_auto_lock_rule"))
    if params.get("validator_candidate_lifecycle_gate_enabled") is not True:
        _issue(
            issues,
            "genesis_validator_candidate_lifecycle_gate_not_enabled",
            params.get("validator_candidate_lifecycle_gate_enabled"),
        )
    if params.get("validator_candidate_node_id_must_match_node_pubkey") is not True:
        _issue(
            issues,
            "genesis_validator_candidate_node_key_binding_not_strict",
            params.get("validator_candidate_node_id_must_match_node_pubkey"),
        )
    if params.get("bft_signing_public_beta_gate_enabled") is not True:
        _issue(
            issues,
            "genesis_bft_signing_public_beta_gate_not_enabled",
            params.get("bft_signing_public_beta_gate_enabled"),
        )
    if params.get("public_mainnet_enabled") is not False:
        _issue(issues, "genesis_public_mainnet_must_start_disabled", params.get("public_mainnet_enabled"))


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
