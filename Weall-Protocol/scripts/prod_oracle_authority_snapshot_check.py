#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from weall.poh.oracle_authority_snapshot import now_ms, verify_authority_snapshot_signature

Json = dict[str, Any]


def _as_str(value: Any) -> str:
    try:
        return str(value or "").strip()
    except Exception:
        return ""


def _split_csv(value: str) -> list[str]:
    out: list[str] = []
    for part in str(value or "").replace("\n", ",").split(","):
        item = part.strip().lower()
        if item:
            out.append(item)
    return out


def _load_snapshot(path: str) -> Json:
    if not path or path == "-":
        raw = sys.stdin.read()
    else:
        raw = Path(path).read_text(encoding="utf-8")
    data = json.loads(raw)
    if not isinstance(data, dict):
        raise ValueError("snapshot_must_be_object")
    return data


def _operator_record(snapshot: Json, operator_account: str) -> Json:
    registry = snapshot.get("registry")
    if not isinstance(registry, dict):
        return {}
    rec = registry.get(operator_account)
    return rec if isinstance(rec, dict) else {}


def check_snapshot(args: argparse.Namespace) -> Json:
    snapshot = _load_snapshot(args.snapshot_file)
    trusted_pubkeys = _split_csv(args.trusted_pubkeys)

    result: Json = {
        "ok": False,
        "signature_ok": False,
        "chain_id_ok": False,
        "genesis_hash_ok": False,
        "tx_index_hash_ok": False,
        "not_expired": False,
        "operator_ok": False,
        "node_pubkey_ok": False,
        "errors": [],
    }

    def fail(reason: str) -> None:
        errors = result.setdefault("errors", [])
        if isinstance(errors, list):
            errors.append(reason)

    result["signature_ok"] = verify_authority_snapshot_signature(
        snapshot, trusted_pubkeys=set(trusted_pubkeys)
    )
    if not result["signature_ok"]:
        fail("bad_or_untrusted_signature")

    expected_chain_id = _as_str(args.expected_chain_id)
    result["chain_id_ok"] = (not expected_chain_id) or _as_str(snapshot.get("chain_id")) == expected_chain_id
    if not result["chain_id_ok"]:
        fail("chain_id_mismatch")

    expected_genesis_hash = _as_str(args.expected_genesis_hash).lower()
    result["genesis_hash_ok"] = (not expected_genesis_hash) or _as_str(snapshot.get("genesis_hash")).lower() == expected_genesis_hash
    if not result["genesis_hash_ok"]:
        fail("genesis_hash_mismatch")

    expected_tx_index_hash = _as_str(args.expected_tx_index_hash).lower()
    result["tx_index_hash_ok"] = (not expected_tx_index_hash) or _as_str(snapshot.get("tx_index_hash")).lower() == expected_tx_index_hash
    if not result["tx_index_hash_ok"]:
        fail("tx_index_hash_mismatch")

    expires_at_ms = snapshot.get("expires_at_ms")
    try:
        result["not_expired"] = int(expires_at_ms) >= now_ms()
    except Exception:
        result["not_expired"] = False
    if not result["not_expired"]:
        fail("snapshot_expired")

    operator_account = _as_str(args.operator_account)
    node_pubkey = _as_str(args.node_pubkey).lower()
    rec = _operator_record(snapshot, operator_account) if operator_account else {}
    result["operator_ok"] = bool(rec and rec.get("eligible") is True)
    if operator_account and not result["operator_ok"]:
        fail("operator_not_authorized")

    pubkeys = rec.get("pubkeys") if isinstance(rec, dict) else []
    result["node_pubkey_ok"] = bool(
        node_pubkey and isinstance(pubkeys, list) and node_pubkey in {_as_str(pk).lower() for pk in pubkeys}
    )
    if node_pubkey and not result["node_pubkey_ok"]:
        fail("node_pubkey_not_authorized")

    required = [
        "signature_ok",
        "chain_id_ok",
        "genesis_hash_ok",
        "tx_index_hash_ok",
        "not_expired",
    ]
    if operator_account:
        required.append("operator_ok")
    if node_pubkey:
        required.append("node_pubkey_ok")

    result["ok"] = all(bool(result.get(k)) for k in required)
    result["snapshot_hash"] = _as_str(snapshot.get("snapshot_hash"))
    result["chain_id"] = _as_str(snapshot.get("chain_id"))
    result["height"] = snapshot.get("height")
    result["operator_account"] = operator_account
    result["node_pubkey"] = node_pubkey
    return result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Verify a signed WeAll oracle-authority snapshot.")
    parser.add_argument("--snapshot-file", default="-", help="Snapshot JSON file, or '-' for stdin.")
    parser.add_argument("--expected-chain-id", default="")
    parser.add_argument("--expected-genesis-hash", default="")
    parser.add_argument("--expected-tx-index-hash", default="")
    parser.add_argument("--trusted-pubkeys", default="", help="Comma-separated trusted Ed25519 pubkeys.")
    parser.add_argument("--operator-account", default="")
    parser.add_argument("--node-pubkey", default="")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)

    try:
        result = check_snapshot(args)
    except Exception as exc:
        result = {"ok": False, "error": str(exc)}

    if args.json:
        print(json.dumps(result, sort_keys=True))
    else:
        print("ok=" + str(bool(result.get("ok"))).lower())
        if not result.get("ok"):
            print("errors=" + ",".join(result.get("errors", []) or [str(result.get("error", "unknown"))]))

    return 0 if result.get("ok") else 2


if __name__ == "__main__":
    raise SystemExit(main())
