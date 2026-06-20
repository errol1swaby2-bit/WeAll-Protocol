#!/usr/bin/env python3
from __future__ import annotations

"""Sign a WeAll public-testnet seed registry.

The private key should normally be supplied through an environment variable so
it never appears in shell history.  The script signs the canonical,
domain-separated payload used by the runtime loader and can also sign validator
endpoint advertisements when endpoint private keys are provided inline through a
local operator-only map file.
"""

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from weall.api.public_seed_registry import (  # noqa: E402
    PublicSeedRegistryError,
    load_public_seed_registry,
    normalize_public_seed_registry,
    registry_signature_payload,
    validator_endpoint_signature_payload,
)
from weall.crypto.sig import sign_ed25519  # noqa: E402

Json = dict[str, Any]


def _pretty(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, indent=2) + "\n"


def _load_json(path: Path) -> Json:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise SystemExit(f"JSON root must be an object: {path}")
    return value


def _env_required(name: str) -> str:
    value = str(os.environ.get(name) or "").strip()
    if not value:
        raise SystemExit(f"missing required environment variable: {name}")
    return value


def _commitments(data: Json) -> Json:
    return {
        "network_id": str(data.get("network_id") or ""),
        "chain_id": str(data.get("chain_id") or ""),
        "genesis_hash": str(data.get("genesis_hash") or ""),
        "protocol_profile_hash": str(data.get("protocol_profile_hash") or ""),
        "tx_index_hash": str(data.get("tx_index_hash") or ""),
    }


def _strip_registry_signature(data: Json) -> Json:
    out = dict(data)
    out.pop("seed_registry_signature", None)
    return out


def sign_registry(data: Json, *, private_key: str, public_key: str) -> Json:
    out = _strip_registry_signature(data)
    out["seed_registry_signer"] = public_key
    out["seed_registry_signature_alg"] = "ed25519/weall.public_seed_registry.v1"
    out["seed_registry_signature"] = sign_ed25519(
        message=registry_signature_payload(out),
        privkey=private_key,
    )
    return out


def sign_validator_endpoints(data: Json, *, endpoint_key_map: Json) -> Json:
    endpoints = data.get("validator_endpoints")
    if not isinstance(endpoints, list):
        return data
    commitments = _commitments(data)
    signed: list[Any] = []
    for endpoint in endpoints:
        if not isinstance(endpoint, dict):
            signed.append(endpoint)
            continue
        account = str(endpoint.get("account_id") or endpoint.get("validator") or "").strip()
        node_pubkey = str(endpoint.get("node_pubkey") or endpoint.get("node_public_key") or endpoint.get("signer") or "").strip()
        key_record = endpoint_key_map.get(node_pubkey) or endpoint_key_map.get(account)
        if not key_record:
            signed.append(endpoint)
            continue
        private_key = str(key_record.get("private_key") if isinstance(key_record, dict) else key_record).strip()
        signer = str(key_record.get("public_key") if isinstance(key_record, dict) else node_pubkey).strip() or node_pubkey
        if not private_key or not signer:
            raise SystemExit(f"endpoint key map entry for {account or node_pubkey} is missing private/public key")
        out = dict(endpoint)
        out["signer"] = signer
        out.setdefault("node_pubkey", signer)
        out["signed"] = True
        out["verified"] = True
        out["signature"] = sign_ed25519(
            message=validator_endpoint_signature_payload(out, commitments=commitments),
            privkey=private_key,
        )
        signed.append(out)
    out_data = dict(data)
    out_data["validator_endpoints"] = signed
    return out_data


def main() -> int:
    parser = argparse.ArgumentParser(description="Sign a WeAll v1.5 public seed registry.")
    parser.add_argument("--input", required=True, help="unsigned or previously signed registry JSON")
    parser.add_argument("--output", required=True, help="signed registry output path")
    parser.add_argument("--registry-private-key-env", default="WEALL_PUBLIC_TESTNET_SEED_REGISTRY_PRIVKEY")
    parser.add_argument("--registry-public-key", default=os.environ.get("WEALL_PUBLIC_TESTNET_SEED_REGISTRY_PUBKEY", ""))
    parser.add_argument("--endpoint-key-map", help="optional local JSON map for signing validator endpoint advertisements; do not commit it")
    parser.add_argument("--allow-local", action="store_true", help="allow localhost/http endpoints for rehearsal signing validation")
    parser.add_argument("--check", action="store_true", help="verify the output would match the existing output")
    args = parser.parse_args()

    input_path = Path(args.input).resolve()
    output_path = Path(args.output).resolve()
    data = _load_json(input_path)

    endpoint_key_map: Json = {}
    if args.endpoint_key_map:
        endpoint_key_map = _load_json(Path(args.endpoint_key_map).resolve())
        data = sign_validator_endpoints(data, endpoint_key_map=endpoint_key_map)

    public_key = str(args.registry_public_key or "").strip()
    if not public_key:
        raise SystemExit("missing registry public key: pass --registry-public-key or WEALL_PUBLIC_TESTNET_SEED_REGISTRY_PUBKEY")
    private_key = _env_required(args.registry_private_key_env)
    signed = sign_registry(data, private_key=private_key, public_key=public_key)

    # Validate as a public-testnet launch registry even when the caller did not
    # pre-export every node runtime variable.  This makes the signing command a
    # safe publication gate and rejects placeholders before writing output.
    os.environ.setdefault("WEALL_PUBLIC_TESTNET", "1")
    os.environ.setdefault("WEALL_PUBLIC_TESTNET_SEED_REGISTRY_PUBKEY", public_key)

    # Validate the signed payload before writing/checking.  This catches
    # placeholders, bad URLs, and bad signatures with the same runtime code used
    # by public observers.
    try:
        normalize_public_seed_registry(signed, allow_local=bool(args.allow_local))
    except PublicSeedRegistryError as exc:
        raise SystemExit(f"signed registry failed runtime validation: {exc}") from exc

    text = _pretty(signed)
    if args.check:
        if not output_path.is_file() or output_path.read_text(encoding="utf-8") != text:
            raise SystemExit(f"signed registry is stale: {output_path}")
        # Also run the file loader path for parity with node startup.
        load_public_seed_registry(str(output_path), allow_local=bool(args.allow_local))
        print(f"OK: signed registry is current: {output_path}")
        return 0

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(text, encoding="utf-8")
    print(f"wrote signed public seed registry: {output_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
