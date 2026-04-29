#!/usr/bin/env python3
"""Build signed WeAll email-oracle request headers for authorized nodes.

This tool is for normal node operators. It never uses SMTP credentials or oracle private keys. It signs the exact HTTP request body with the local
WeAll node/account key, producing the headers required by the production email
WeAll-hosted oracle service.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import shlex
import sys
import time
import uuid
from pathlib import Path
from typing import Any

from nacl.signing import SigningKey

Json = dict[str, Any]

HEADER_ACCOUNT = "x-weall-oracle-account"
HEADER_PUBKEY = "x-weall-oracle-pubkey"
HEADER_CHAIN_ID = "x-weall-oracle-chain-id"
HEADER_GENESIS_HASH = "x-weall-oracle-genesis-hash"
HEADER_TIMESTAMP = "x-weall-oracle-timestamp"
HEADER_NONCE = "x-weall-oracle-nonce"
HEADER_BODY_HASH = "x-weall-oracle-body-sha256"
HEADER_SIGNATURE = "x-weall-oracle-signature"


def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _read_secret(value: str | None, file_value: str | None) -> str:
    raw = str(value or "").strip()
    if raw:
        return raw
    path = str(file_value or "").strip()
    if not path:
        return ""
    return Path(path).read_text(encoding="utf-8").strip()


def _json_dumps(data: Any) -> str:
    return json.dumps(data, separators=(",", ":"), sort_keys=False)


def _canonical_oracle_signature_material(
    *,
    method: str,
    path: str,
    chain_id: str,
    genesis_hash: str,
    ts_ms: int,
    nonce: str,
    body_sha256: str,
    operator_account: str,
    node_pubkey: str,
) -> bytes:
    material = "\n".join(
        [
            "weall-email-oracle-v1",
            method.strip().upper(),
            path.strip(),
            chain_id.strip(),
            genesis_hash.strip().lower(),
            str(int(ts_ms)),
            nonce.strip(),
            body_sha256.strip().lower(),
            operator_account.strip(),
            node_pubkey.strip().lower(),
            "",
        ]
    )
    return material.encode("utf-8")


def _body_bytes(args: argparse.Namespace) -> bytes:
    supplied = [bool(args.body), bool(args.body_file), bool(args.json_file)]
    if sum(1 for item in supplied if item) > 1:
        raise SystemExit("provide only one of --body, --body-file, or --json-file")
    if args.body:
        return str(args.body).encode("utf-8")
    if args.body_file:
        return Path(args.body_file).read_bytes()
    if args.json_file:
        parsed = json.loads(Path(args.json_file).read_text(encoding="utf-8"))
        return _json_dumps(parsed).encode("utf-8")
    if not sys.stdin.isatty():
        return sys.stdin.buffer.read()
    return b"{}"


def _headers(
    *,
    method: str,
    path: str,
    body: bytes,
    account: str,
    pubkey: str,
    privkey: str,
    chain_id: str,
    genesis_hash: str,
    nonce: str | None = None,
    timestamp_ms: int | None = None,
) -> dict[str, str]:
    account_norm = str(account or "").strip()
    pubkey_norm = str(pubkey or "").strip().lower()
    privkey_norm = str(privkey or "").strip().lower()
    chain_id_norm = str(chain_id or "").strip()
    genesis_hash_norm = str(genesis_hash or "").strip().lower()

    missing = []
    if not account_norm:
        missing.append("operator account")
    if not pubkey_norm:
        missing.append("node public key")
    if not privkey_norm:
        missing.append("node private key")
    if not chain_id_norm:
        missing.append("chain id")
    if not genesis_hash_norm:
        missing.append("genesis hash")
    if missing:
        raise SystemExit("missing required signing material: " + ", ".join(missing))

    try:
        signing_key = SigningKey(bytes.fromhex(privkey_norm))
    except Exception as exc:
        raise SystemExit("invalid node private key hex") from exc

    ts_ms = int(timestamp_ms if timestamp_ms is not None else int(time.time() * 1000))
    nonce_norm = str(nonce or uuid.uuid4()).strip()
    body_sha256 = _sha256_hex(body)
    material = _canonical_oracle_signature_material(
        method=method,
        path=path,
        chain_id=chain_id_norm,
        genesis_hash=genesis_hash_norm,
        ts_ms=ts_ms,
        nonce=nonce_norm,
        body_sha256=body_sha256,
        operator_account=account_norm,
        node_pubkey=pubkey_norm,
    )
    signature = signing_key.sign(material).signature.hex()
    return {
        HEADER_ACCOUNT: account_norm,
        HEADER_PUBKEY: pubkey_norm,
        HEADER_CHAIN_ID: chain_id_norm,
        HEADER_GENESIS_HASH: genesis_hash_norm,
        HEADER_TIMESTAMP: str(ts_ms),
        HEADER_NONCE: nonce_norm,
        HEADER_BODY_HASH: body_sha256,
        HEADER_SIGNATURE: signature,
    }


def _curl_command(*, url: str, headers: dict[str, str], body: bytes) -> str:
    parts = ["curl", "-sS", "-X", "POST"]
    for key, value in headers.items():
        parts.extend(["-H", f"{key}: {value}"])
    parts.extend(["-H", "content-type: application/json", "--data-binary", body.decode("utf-8", errors="replace"), url])
    return " ".join(shlex.quote(p) for p in parts)


def main() -> int:
    parser = argparse.ArgumentParser(description="Sign a WeAll email-oracle HTTP request as an authorized node account.")
    parser.add_argument("--method", default="POST", help="HTTP method, default POST")
    parser.add_argument("--path", required=True, help="Oracle path, e.g. /v1/poh/email/begin or /v1/poh/email/complete")
    parser.add_argument("--url", default="", help="Optional full oracle URL used when --curl is set")
    parser.add_argument("--body", default="", help="Exact JSON request body string to sign")
    parser.add_argument("--body-file", default="", help="File containing exact request body bytes to sign")
    parser.add_argument("--json-file", default="", help="JSON file to compact and sign")
    parser.add_argument("--account", default=os.environ.get("WEALL_VALIDATOR_ACCOUNT") or os.environ.get("WEALL_ORACLE_OPERATOR_ACCOUNT") or "")
    parser.add_argument("--pubkey", default=os.environ.get("WEALL_NODE_PUBKEY") or "")
    parser.add_argument("--privkey", default=os.environ.get("WEALL_NODE_PRIVKEY") or "")
    parser.add_argument("--privkey-file", default=os.environ.get("WEALL_NODE_PRIVKEY_FILE") or "")
    parser.add_argument("--chain-id", default=os.environ.get("WEALL_CHAIN_ID") or os.environ.get("WEALL_EXPECTED_CHAIN_ID") or "")
    parser.add_argument("--genesis-hash", default=os.environ.get("WEALL_EXPECTED_GENESIS_HASH") or os.environ.get("WEALL_ORACLE_GENESIS_HASH") or "")
    parser.add_argument("--nonce", default="")
    parser.add_argument("--timestamp-ms", type=int, default=None)
    parser.add_argument("--curl", action="store_true", help="Print a curl command instead of JSON")
    args = parser.parse_args()

    body = _body_bytes(args)
    privkey = _read_secret(args.privkey, args.privkey_file)
    headers = _headers(
        method=args.method,
        path=args.path,
        body=body,
        account=args.account,
        pubkey=args.pubkey,
        privkey=privkey,
        chain_id=args.chain_id,
        genesis_hash=args.genesis_hash,
        nonce=args.nonce or None,
        timestamp_ms=args.timestamp_ms,
    )

    if args.curl:
        url = str(args.url or "").strip()
        if not url:
            raise SystemExit("--curl requires --url")
        print(_curl_command(url=url, headers=headers, body=body))
    else:
        print(_json_dumps({"ok": True, "headers": headers, "body_sha256": headers[HEADER_BODY_HASH]}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
