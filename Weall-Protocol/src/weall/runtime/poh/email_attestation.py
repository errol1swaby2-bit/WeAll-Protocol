from __future__ import annotations

"""email_control_attestation_v1 canonical format and verification."""

import hashlib
import json
from typing import Any

from weall.crypto.sig import sign_ed25519, verify_ed25519_signature
from weall.runtime.poh.oracle_registry import ORACLE_TYPE_POH_EMAIL_TIER1, require_active_oracle

Json = dict[str, Any]

ATTESTATION_TYPE = "email_control_attestation_v1"
_FORBIDDEN_RAW_FIELDS = frozenset(
    {
        "e" + "mail",
        "raw_email",
        "normalized_email",
        "email_address",
        "verification_code",
        "code",
        "secret",
        "challenge_secret",
        "private_key",
        "oracle_private_key",
    }
)
_CANONICAL_FIELDS = (
    "type",
    "chain_id",
    "account_id",
    "email_hash",
    "domain_hash",
    "challenge_id",
    "issued_at_height",
    "expires_at_height",
    "oracle_id",
    "proof_commitment",
)


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


def _canon_json(payload: Json) -> str:
    return json.dumps(payload, ensure_ascii=False, separators=(",", ":"), sort_keys=True)


def sha256_hex_text(value: str) -> str:
    return hashlib.sha256(str(value or "").encode("utf-8")).hexdigest()


def normalize_email_for_oracle(email: str) -> str:
    value = _as_str(email).lower()
    if "@" not in value or value.startswith("@") or value.endswith("@"):
        raise ValueError("invalid_email")
    return value


def split_email_domain(normalized_email: str) -> str:
    value = normalize_email_for_oracle(normalized_email)
    return value.rsplit("@", 1)[1]


def email_hash_for_attestation(*, normalized_email: str, salt: str, account_id: str) -> str:
    material = "\n".join(
        [
            "weall-email-control-hash-v1",
            normalize_email_for_oracle(normalized_email),
            _as_str(salt),
            _as_str(account_id),
            "",
        ]
    )
    return sha256_hex_text(material)


def domain_hash_for_attestation(*, normalized_email: str, salt: str, account_id: str) -> str:
    material = "\n".join(
        [
            "weall-email-domain-hash-v1",
            split_email_domain(normalized_email),
            _as_str(salt),
            _as_str(account_id),
            "",
        ]
    )
    return sha256_hex_text(material)


def reject_raw_identity_fields(attestation: Json) -> None:
    for key in attestation.keys():
        if _as_str(key).lower() in _FORBIDDEN_RAW_FIELDS:
            raise ValueError("raw_identity_field_forbidden")


def canonical_attestation_payload(attestation: Json) -> Json:
    if not isinstance(attestation, dict):
        raise ValueError("attestation_not_object")
    reject_raw_identity_fields(attestation)
    payload: Json = {
        "type": _as_str(attestation.get("type") or ATTESTATION_TYPE),
        "chain_id": _as_str(attestation.get("chain_id") or ""),
        "account_id": _as_str(attestation.get("account_id") or ""),
        "email_hash": _as_str(attestation.get("email_hash") or ""),
        "domain_hash": _as_str(attestation.get("domain_hash") or ""),
        "challenge_id": _as_str(attestation.get("challenge_id") or ""),
        "issued_at_height": _as_int(attestation.get("issued_at_height"), 0),
        "expires_at_height": _as_int(attestation.get("expires_at_height"), 0),
        "oracle_id": _as_str(attestation.get("oracle_id") or ""),
        "proof_commitment": _as_str(attestation.get("proof_commitment") or ""),
    }
    if payload["type"] != ATTESTATION_TYPE:
        raise ValueError("bad_attestation_type")
    for required in (
        "account_id",
        "email_hash",
        "domain_hash",
        "challenge_id",
        "oracle_id",
        "proof_commitment",
    ):
        if not payload[required]:
            raise ValueError(f"missing_{required}")
    if payload["issued_at_height"] < 0:
        raise ValueError("bad_issued_at_height")
    if payload["expires_at_height"] <= payload["issued_at_height"]:
        raise ValueError("bad_expires_at_height")
    expected_commitment = proof_commitment_for_payload({k: payload[k] for k in _CANONICAL_FIELDS if k != "proof_commitment"})
    if payload["proof_commitment"] != expected_commitment:
        raise ValueError("proof_commitment_mismatch")
    return payload


def proof_commitment_for_payload(payload_without_commitment: Json) -> str:
    safe = {
        "type": _as_str(payload_without_commitment.get("type") or ATTESTATION_TYPE),
        "chain_id": _as_str(payload_without_commitment.get("chain_id") or ""),
        "account_id": _as_str(payload_without_commitment.get("account_id") or ""),
        "email_hash": _as_str(payload_without_commitment.get("email_hash") or ""),
        "domain_hash": _as_str(payload_without_commitment.get("domain_hash") or ""),
        "challenge_id": _as_str(payload_without_commitment.get("challenge_id") or ""),
        "issued_at_height": _as_int(payload_without_commitment.get("issued_at_height"), 0),
        "expires_at_height": _as_int(payload_without_commitment.get("expires_at_height"), 0),
        "oracle_id": _as_str(payload_without_commitment.get("oracle_id") or ""),
    }
    return hashlib.sha256(("weall-proof-commitment-v1\n" + _canon_json(safe)).encode("utf-8")).hexdigest()


def canonical_attestation_message(attestation: Json) -> bytes:
    payload = canonical_attestation_payload(attestation)
    return ("weall-email-control-attestation-v1\n" + _canon_json(payload)).encode("utf-8")


def build_unsigned_email_control_attestation_v1(
    *,
    account_id: str,
    email_hash: str,
    domain_hash: str,
    challenge_id: str,
    issued_at_height: int,
    expires_at_height: int,
    oracle_id: str,
    chain_id: str = "",
) -> Json:
    base: Json = {
        "type": ATTESTATION_TYPE,
        "chain_id": _as_str(chain_id),
        "account_id": _as_str(account_id),
        "email_hash": _as_str(email_hash),
        "domain_hash": _as_str(domain_hash),
        "challenge_id": _as_str(challenge_id),
        "issued_at_height": int(issued_at_height),
        "expires_at_height": int(expires_at_height),
        "oracle_id": _as_str(oracle_id),
    }
    base["proof_commitment"] = proof_commitment_for_payload(base)
    # Validate before returning so malformed callers fail early.
    canonical_attestation_payload(base)
    return base


def sign_email_control_attestation_v1(attestation_without_signature: Json, *, oracle_private_key: str) -> Json:
    payload = canonical_attestation_payload(attestation_without_signature)
    out = dict(payload)
    out["oracle_signature"] = sign_ed25519(
        message=canonical_attestation_message(payload),
        privkey=oracle_private_key,
        encoding="hex",
    )
    return out


def verify_email_control_attestation_v1_signature(attestation: Json, *, oracle_pubkey: str) -> bool:
    sig = _as_str(attestation.get("oracle_signature") or "")
    if not sig:
        return False
    try:
        msg = canonical_attestation_message(attestation)
    except ValueError:
        return False
    return verify_ed25519_signature(message=msg, sig=sig, pubkey=_as_str(oracle_pubkey).lower())


def validate_attestation_for_state(
    state: Json,
    attestation: Json,
    *,
    account_id: str,
    current_height: int | None = None,
) -> tuple[bool, str, Json | None, Json | None]:
    try:
        payload = canonical_attestation_payload(attestation)
    except ValueError as exc:
        return False, str(exc), None, None

    expected_account = _as_str(account_id)
    if payload["account_id"] != expected_account:
        return False, "attestation_account_mismatch", None, None

    expected_chain_id = _as_str(state.get("chain_id") or "")
    if payload.get("chain_id") and expected_chain_id and payload["chain_id"] != expected_chain_id:
        return False, "attestation_chain_id_mismatch", None, None

    height = _as_int(state.get("height"), 0) if current_height is None else int(current_height)
    if height < _as_int(payload.get("issued_at_height"), 0):
        return False, "attestation_from_future", None, None
    if height > _as_int(payload.get("expires_at_height"), 0):
        return False, "attestation_expired", None, None

    try:
        oracle = require_active_oracle(
            state,
            oracle_id=payload["oracle_id"],
            oracle_type=ORACLE_TYPE_POH_EMAIL_TIER1,
            at_height=height,
        )
    except ValueError as exc:
        return False, str(exc), None, None

    if not verify_email_control_attestation_v1_signature(attestation, oracle_pubkey=_as_str(oracle.get("oracle_pubkey"))):
        return False, "bad_oracle_signature", None, None

    return True, "ok", payload, oracle
