#!/usr/bin/env python3
"""Verify a signed/root-bound WeAll email-oracle authority snapshot.

This is a node-operator preflight helper. It proves that the authority data used
by the WeAll-hosted PoH email oracle is bound to the expected chain identity and signed by a
trusted authority signer. It does not require SMTP credentials or oracle private keys.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from weall.poh.oracle_authority_snapshot import verify_authority_snapshot_signature  # noqa: E402

Json = dict[str, Any]


def _json_dumps(data: Any) -> str:
    return json.dumps(data, separators=(",", ":"), sort_keys=True)


def _split_csv(value: str) -> list[str]:
    return [part.strip().lower() for part in str(value or "").split(",") if part.strip()]


def _fetch_json(url: str, timeout_s: int) -> Json:
    req = urllib.request.Request(url, headers={"accept": "application/json"}, method="GET")
    try:
        with urllib.request.urlopen(req, timeout=timeout_s) as resp:
            parsed = json.loads(resp.read().decode("utf-8"))
    except urllib.error.URLError as exc:
        raise RuntimeError(f"authority_snapshot_fetch_failed:{exc}") from exc
    if not isinstance(parsed, dict):
        raise RuntimeError("authority_snapshot_not_object")
    return parsed


def _snapshot_from_args(args: argparse.Namespace) -> Json:
    if args.snapshot_file:
        parsed = json.loads(Path(args.snapshot_file).read_text(encoding="utf-8"))
        if not isinstance(parsed, dict):
            raise RuntimeError("snapshot_file_not_object")
        return parsed
    base = str(args.authority_url or "").rstrip("/")
    if not base:
        raise RuntimeError("missing_authority_url_or_snapshot_file")
    if base.endswith("/v1/poh/email/oracle-authority"):
        url = base
    else:
        url = base + "/v1/poh/email/oracle-authority"
    return _fetch_json(url, int(args.timeout_s))


def _record_for(snapshot: Json, account: str) -> Json:
    registry = snapshot.get("registry")
    if not isinstance(registry, dict):
        return {}
    rec = registry.get(account)
    return rec if isinstance(rec, dict) else {}


def validate_snapshot(snapshot: Json, args: argparse.Namespace) -> Json:
    issues: list[str] = []
    now_ms = int(time.time() * 1000)

    expected_chain = str(args.expected_chain_id or "").strip()
    expected_genesis = str(args.expected_genesis_hash or "").strip().lower()
    expected_tx_index = str(args.expected_tx_index_hash or "").strip().lower()
    trusted_pubkeys = _split_csv(args.trusted_pubkeys)
    operator_account = str(args.operator_account or "").strip()
    node_pubkey = str(args.node_pubkey or "").strip().lower()

    if snapshot.get("type") != "weall_email_oracle_authority_snapshot":
        issues.append("authority_snapshot_wrong_type")
    if int(snapshot.get("version") or 0) != 1:
        issues.append("authority_snapshot_wrong_version")
    if expected_chain and str(snapshot.get("chain_id") or "").strip() != expected_chain:
        issues.append("authority_snapshot_chain_id_mismatch")
    if expected_genesis and str(snapshot.get("genesis_hash") or "").strip().lower() != expected_genesis:
        issues.append("authority_snapshot_genesis_hash_mismatch")
    if expected_tx_index and str(snapshot.get("tx_index_hash") or "").strip().lower() != expected_tx_index:
        issues.append("authority_snapshot_tx_index_hash_mismatch")

    height = int(snapshot.get("height") or 0)
    if height < int(args.min_height):
        issues.append("authority_snapshot_height_too_low")

    generated_at = int(snapshot.get("generated_at_ms") or 0)
    expires_at = int(snapshot.get("expires_at_ms") or 0)
    if not generated_at:
        issues.append("authority_snapshot_missing_generated_at")
    if not expires_at or expires_at <= now_ms:
        issues.append("authority_snapshot_expired")
    if generated_at > now_ms + int(args.future_skew_ms):
        issues.append("authority_snapshot_generated_in_future")
    if int(args.max_age_ms) > 0 and generated_at and now_ms - generated_at > int(args.max_age_ms):
        issues.append("authority_snapshot_too_old")

    if not str(snapshot.get("state_root") or "").strip():
        issues.append("authority_snapshot_missing_state_root")
    if not str(snapshot.get("tx_index_hash") or "").strip():
        issues.append("authority_snapshot_missing_tx_index_hash")
    if not str(snapshot.get("snapshot_hash") or "").strip():
        issues.append("authority_snapshot_missing_hash")

    signature_ok = verify_authority_snapshot_signature(snapshot, trusted_pubkeys=trusted_pubkeys)
    if not signature_ok:
        issues.append("authority_snapshot_signature_invalid")

    record: Json = {}
    if operator_account:
        record = _record_for(snapshot, operator_account)
        if not record:
            issues.append("operator_account_not_in_authority_snapshot")
        else:
            if not bool(record.get("eligible")):
                issues.append("operator_account_not_eligible")
            if str(record.get("status") or "") != "active":
                issues.append("operator_account_not_active")
            if int(record.get("poh_tier") or 0) < 3:
                issues.append("operator_account_not_tier3")
            if not bool(record.get("active_node_operator")):
                issues.append("operator_account_not_active_node_operator")
            if int(record.get("reputation_units") or 0) <= 0:
                issues.append("operator_account_non_positive_reputation")
            if bool(record.get("locked")):
                issues.append("operator_account_locked")
            if bool(record.get("banned")):
                issues.append("operator_account_banned")
            pubkeys = {str(pk or "").strip().lower() for pk in record.get("pubkeys") or []}
            if node_pubkey and node_pubkey not in pubkeys:
                issues.append("node_pubkey_not_authorized_for_operator")

    return {
        "ok": not issues,
        "issues": issues,
        "chain_id": snapshot.get("chain_id"),
        "genesis_hash": snapshot.get("genesis_hash"),
        "tx_index_hash": snapshot.get("tx_index_hash"),
        "height": height,
        "state_root": snapshot.get("state_root"),
        "snapshot_hash": snapshot.get("snapshot_hash"),
        "signature_ok": signature_ok,
        "operator_account": operator_account,
        "node_pubkey": node_pubkey,
        "operator_record": record if args.include_record else {},
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Verify WeAll email-oracle signed authority snapshot.")
    parser.add_argument("--authority-url", default=os.environ.get("WEALL_CHAIN_AUTHORITY_URL") or os.environ.get("WEALL_API_BASE") or "")
    parser.add_argument("--snapshot-file", default="")
    parser.add_argument("--expected-chain-id", default=os.environ.get("WEALL_EXPECTED_CHAIN_ID") or os.environ.get("WEALL_CHAIN_ID") or "")
    parser.add_argument("--expected-genesis-hash", default=os.environ.get("WEALL_EXPECTED_GENESIS_HASH") or os.environ.get("WEALL_ORACLE_GENESIS_HASH") or "")
    parser.add_argument("--expected-tx-index-hash", default=os.environ.get("WEALL_EXPECTED_TX_INDEX_HASH") or "")
    parser.add_argument("--trusted-pubkeys", default=os.environ.get("WEALL_ORACLE_AUTHORITY_PUBKEYS") or os.environ.get("WEALL_TRUSTED_AUTHORITY_PUBKEYS") or "")
    parser.add_argument("--operator-account", default=os.environ.get("WEALL_VALIDATOR_ACCOUNT") or os.environ.get("WEALL_ORACLE_OPERATOR_ACCOUNT") or "")
    parser.add_argument("--node-pubkey", default=os.environ.get("WEALL_NODE_PUBKEY") or "")
    parser.add_argument("--min-height", type=int, default=int(os.environ.get("WEALL_MIN_AUTHORITY_HEIGHT") or "0"))
    parser.add_argument("--max-age-ms", type=int, default=int(os.environ.get("WEALL_AUTHORITY_SNAPSHOT_MAX_AGE_MS") or "120000"))
    parser.add_argument("--future-skew-ms", type=int, default=30000)
    parser.add_argument("--timeout-s", type=int, default=10)
    parser.add_argument("--include-record", action="store_true")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()

    try:
        snapshot = _snapshot_from_args(args)
        result = validate_snapshot(snapshot, args)
    except Exception as exc:
        result = {"ok": False, "issues": [str(exc)]}

    if args.json:
        print(_json_dumps(result))
    else:
        if result.get("ok"):
            print("OK: signed oracle authority snapshot verified")
        else:
            print("ERROR: signed oracle authority snapshot check failed", file=sys.stderr)
            for issue in result.get("issues") or []:
                print(f"- {issue}", file=sys.stderr)
    return 0 if result.get("ok") else 1


if __name__ == "__main__":
    raise SystemExit(main())
