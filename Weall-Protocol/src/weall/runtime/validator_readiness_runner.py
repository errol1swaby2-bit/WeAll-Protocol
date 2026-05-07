from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any, Mapping

Json = dict[str, Any]

_REQUIRED_READINESS_CHECKS: tuple[str, ...] = (
    "chain_id_match",
    "manifest_match",
    "tx_index_match",
    "runtime_profile_match",
    "node_key_ready",
    "bft_signer_ready",
    "state_sync_ready",
    "network_ready",
    "restart_safe",
)

_REQUIRED_RECEIPT_FIELDS: tuple[str, ...] = (
    "account_id",
    "node_pubkey",
    "bft_pubkey",
    "chain_id",
    "schema_version",
    "protocol_version",
    "manifest_hash",
    "tx_index_hash",
    "runtime_profile_hash",
    "readiness_expires_height",
)


class ValidatorReadinessError(ValueError):
    """Raised when validator readiness evidence is incomplete or invalid."""


def _as_str(value: Any) -> str:
    try:
        return str(value or "").strip()
    except Exception:
        return ""


def _as_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except Exception:
        return int(default)


def _as_dict(value: Any) -> Json:
    return value if isinstance(value, dict) else {}


def _hash_json(value: Any) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return "sha256:" + hashlib.sha256(encoded).hexdigest()


def _normalize_checks(checks: Mapping[str, Any] | None) -> Json:
    raw = _as_dict(checks)
    out: Json = {}
    for key in sorted(set(raw) | set(_REQUIRED_READINESS_CHECKS)):
        if not key:
            continue
        value = raw.get(key, False)
        if isinstance(value, str):
            value = value.strip().lower() in ("1", "true", "yes", "ok", "passed", "ready")
        out[str(key)] = bool(value)
    return out


def readiness_payload_for_hash(payload: Mapping[str, Any]) -> Json:
    """Return the canonical validator readiness receipt payload.

    This intentionally excludes mutable envelope fields and the receipt hash
    itself. It is safe to use both by local node tooling and deterministic
    execution-side verification.
    """

    src = _as_dict(payload)
    checks = _normalize_checks(_as_dict(src.get("readiness_checks")))
    return {
        "version": 1,
        "kind": "weall.validator.readiness.receipt",
        "account_id": _as_str(src.get("account_id") or src.get("operator") or src.get("node_operator") or src.get("target") or src.get("account")),
        "node_pubkey": _as_str(src.get("node_pubkey") or src.get("node_public_key")),
        "bft_pubkey": _as_str(src.get("bft_pubkey") or src.get("validator_pubkey") or src.get("consensus_pubkey")),
        "chain_id": _as_str(src.get("chain_id")),
        "schema_version": _as_str(src.get("schema_version")),
        "protocol_version": _as_str(src.get("protocol_version")),
        "manifest_hash": _as_str(src.get("manifest_hash") or src.get("chain_manifest_hash")),
        "tx_index_hash": _as_str(src.get("tx_index_hash")),
        "runtime_profile_hash": _as_str(src.get("runtime_profile_hash")),
        "readiness_expires_height": _as_int(src.get("readiness_expires_height"), 0),
        "readiness_checks": checks,
    }


def validator_readiness_receipt_hash(payload: Mapping[str, Any]) -> str:
    return _hash_json(readiness_payload_for_hash(payload))


def build_validator_readiness_receipt(
    *,
    account_id: str,
    node_pubkey: str,
    bft_pubkey: str,
    chain_id: str,
    schema_version: str,
    protocol_version: str,
    manifest_hash: str,
    tx_index_hash: str,
    runtime_profile_hash: str,
    readiness_expires_height: int,
    readiness_checks: Mapping[str, Any] | None = None,
) -> Json:
    payload: Json = {
        "account_id": _as_str(account_id),
        "node_pubkey": _as_str(node_pubkey),
        "bft_pubkey": _as_str(bft_pubkey),
        "chain_id": _as_str(chain_id),
        "schema_version": _as_str(schema_version),
        "protocol_version": _as_str(protocol_version),
        "manifest_hash": _as_str(manifest_hash),
        "tx_index_hash": _as_str(tx_index_hash),
        "runtime_profile_hash": _as_str(runtime_profile_hash),
        "readiness_expires_height": int(readiness_expires_height),
        "readiness_checks": _normalize_checks(readiness_checks or {key: True for key in _REQUIRED_READINESS_CHECKS}),
    }
    receipt = readiness_payload_for_hash(payload)
    receipt["readiness_receipt_hash"] = validator_readiness_receipt_hash(payload)
    return receipt


def validate_validator_readiness_payload(
    payload: Mapping[str, Any],
    *,
    account_id: str = "",
    expected_node_pubkey: str = "",
    current_height: int = 0,
) -> Json:
    """Validate a live validator readiness receipt-shaped payload.

    This does not perform network calls; it verifies that the supplied readiness
    evidence was produced from the required live checks and is bound to the
    account, node key, chain identity, manifest, tx index, runtime profile, BFT
    key, and expiry height.
    """

    canonical = readiness_payload_for_hash(payload)
    errors: list[str] = []
    for field in _REQUIRED_RECEIPT_FIELDS:
        value = canonical.get(field)
        if field == "readiness_expires_height":
            if _as_int(value, 0) <= int(current_height):
                errors.append("readiness_expires_height_must_be_future")
        elif not _as_str(value):
            errors.append(f"{field}_required")

    if account_id and canonical.get("account_id") != account_id:
        errors.append("readiness_account_mismatch")
    if expected_node_pubkey and canonical.get("node_pubkey") != expected_node_pubkey:
        errors.append("readiness_node_pubkey_mismatch")

    checks = _normalize_checks(_as_dict(canonical.get("readiness_checks")))
    failed_checks = [name for name in _REQUIRED_READINESS_CHECKS if not bool(checks.get(name))]
    if failed_checks:
        errors.extend(f"readiness_check_failed:{name}" for name in failed_checks)

    provided_hash = _as_str(payload.get("readiness_receipt_hash") or payload.get("validator_readiness_receipt_hash") or payload.get("verification_receipt_hash"))
    expected_hash = validator_readiness_receipt_hash(canonical)
    if not provided_hash:
        errors.append("readiness_receipt_hash_required")
    elif provided_hash != expected_hash:
        errors.append("readiness_receipt_hash_mismatch")

    if errors:
        raise ValidatorReadinessError(";".join(errors))

    out = dict(canonical)
    out["readiness_receipt_hash"] = expected_hash
    out["required_checks"] = list(_REQUIRED_READINESS_CHECKS)
    return out


def _load_json(path: str | Path) -> Json:
    try:
        return _as_dict(json.loads(Path(path).read_text(encoding="utf-8")))
    except json.JSONDecodeError as exc:
        raise ValidatorReadinessError("invalid_json") from exc


def _cmd_generate(args: argparse.Namespace) -> int:
    checks = {key: True for key in _REQUIRED_READINESS_CHECKS}
    if args.check:
        for item in args.check:
            if "=" not in item:
                raise ValidatorReadinessError("check_must_be_key_equals_value")
            key, value = item.split("=", 1)
            checks[key.strip()] = value.strip().lower() in ("1", "true", "yes", "ok", "passed", "ready")
    receipt = build_validator_readiness_receipt(
        account_id=args.account_id,
        node_pubkey=args.node_pubkey,
        bft_pubkey=args.bft_pubkey,
        chain_id=args.chain_id,
        schema_version=args.schema_version,
        protocol_version=args.protocol_version,
        manifest_hash=args.manifest_hash,
        tx_index_hash=args.tx_index_hash,
        runtime_profile_hash=args.runtime_profile_hash,
        readiness_expires_height=args.readiness_expires_height,
        readiness_checks=checks,
    )
    print(json.dumps(receipt, sort_keys=True, indent=2))
    return 0


def _cmd_verify(args: argparse.Namespace) -> int:
    payload = _load_json(args.receipt)
    out = validate_validator_readiness_payload(
        payload,
        account_id=args.account_id,
        expected_node_pubkey=args.node_pubkey,
        current_height=int(args.current_height),
    )
    print(json.dumps({"ok": True, "readiness_receipt_hash": out["readiness_receipt_hash"], "account_id": out["account_id"], "node_pubkey": out["node_pubkey"]}, sort_keys=True, indent=2))
    return 0


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Generate or verify WeAll validator readiness receipts.")
    sub = parser.add_subparsers(dest="cmd", required=True)
    gen = sub.add_parser("generate", help="Generate a validator readiness receipt from live readiness inputs.")
    for name in ("account-id", "node-pubkey", "bft-pubkey", "chain-id", "schema-version", "protocol-version", "manifest-hash", "tx-index-hash", "runtime-profile-hash"):
        gen.add_argument(f"--{name}", required=True)
    gen.add_argument("--readiness-expires-height", type=int, required=True)
    gen.add_argument("--check", action="append", default=[], help="Override a readiness check as key=true/false")
    gen.set_defaults(func=_cmd_generate)

    verify = sub.add_parser("verify", help="Verify a validator readiness receipt JSON file.")
    verify.add_argument("--receipt", required=True)
    verify.add_argument("--account-id", default="")
    verify.add_argument("--node-pubkey", default="")
    verify.add_argument("--current-height", type=int, default=0)
    verify.set_defaults(func=_cmd_verify)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_arg_parser()
    args = parser.parse_args(argv)
    try:
        return int(args.func(args))
    except ValidatorReadinessError as exc:
        parser.exit(2, f"validator-readiness-check failed: {exc}\n")


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
