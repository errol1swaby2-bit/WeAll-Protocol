from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Any

from .tx_admission_types import TxEnvelope

Json = dict[str, Any]

ACCOUNT_REGISTRATION_WORK_VERSION = "sha256-v1"
ACCOUNT_REGISTRATION_WORK_DOMAIN = "weall.account_register_work.v1"
ACCOUNT_REGISTRATION_WORK_MIN_BITS = 1
ACCOUNT_REGISTRATION_WORK_MAX_BITS = 30
ACCOUNT_REGISTRATION_WORK_MAX_NONCE = (1 << 53) - 1

# A15-F003 production scarcity floor.  "Nonzero" is not a meaningful security
# invariant by itself: one-bit work would make permanent root-visible account
# creation effectively free.  Production and the pinned public testnet therefore
# fail closed below the currently reviewed 16-bit admission floor.
ACCOUNT_REGISTRATION_WORK_PRODUCTION_MIN_BITS = 16
ACCOUNT_REGISTRATION_WORK_PRODUCTION_CHAIN_IDS = frozenset({"weall-prod", "weall-testnet-v1"})


@dataclass(frozen=True)
class AccountRegistrationWorkPolicy:
    required: bool
    difficulty_bits: int
    valid: bool = True
    reason: str = ""


def _as_params(state: Json) -> Json:
    params = state.get("params") if isinstance(state, dict) else None
    return params if isinstance(params, dict) else {}


def _policy_bool(value: Any) -> tuple[bool, bool]:
    if isinstance(value, bool):
        return value, True
    if value is None:
        return False, True
    text = str(value).strip().lower()
    if text in {"1", "true", "yes", "on"}:
        return True, True
    if text in {"0", "false", "no", "off", ""}:
        return False, True
    return False, False


def account_registration_work_policy(state: Json) -> AccountRegistrationWorkPolicy:
    params = _as_params(state)
    required, required_valid = _policy_bool(params.get("account_registration_work_required"))
    if not required_valid:
        return AccountRegistrationWorkPolicy(
            required=True,
            difficulty_bits=0,
            valid=False,
            reason="registration_work_required_policy_invalid",
        )
    if not required:
        return AccountRegistrationWorkPolicy(required=False, difficulty_bits=0)

    raw_bits = params.get("account_registration_work_difficulty_bits")
    if isinstance(raw_bits, bool):
        return AccountRegistrationWorkPolicy(
            required=True,
            difficulty_bits=0,
            valid=False,
            reason="registration_work_difficulty_invalid",
        )
    try:
        bits = int(raw_bits)
    except Exception:
        return AccountRegistrationWorkPolicy(
            required=True,
            difficulty_bits=0,
            valid=False,
            reason="registration_work_difficulty_invalid",
        )
    if bits < ACCOUNT_REGISTRATION_WORK_MIN_BITS or bits > ACCOUNT_REGISTRATION_WORK_MAX_BITS:
        return AccountRegistrationWorkPolicy(
            required=True,
            difficulty_bits=bits,
            valid=False,
            reason="registration_work_difficulty_out_of_range",
        )

    chain_id = str(state.get("chain_id") or "").strip() if isinstance(state, dict) else ""
    if (
        chain_id in ACCOUNT_REGISTRATION_WORK_PRODUCTION_CHAIN_IDS
        and bits < ACCOUNT_REGISTRATION_WORK_PRODUCTION_MIN_BITS
    ):
        return AccountRegistrationWorkPolicy(
            required=True,
            difficulty_bits=bits,
            valid=False,
            reason="registration_work_difficulty_below_production_minimum",
        )

    return AccountRegistrationWorkPolicy(required=True, difficulty_bits=bits)


def _payload_without_work(payload: Any) -> Json:
    if not isinstance(payload, dict):
        return {}
    return {
        str(k): v
        for k, v in payload.items()
        if str(k) not in {"registration_work_version", "registration_work_nonce"}
    }


def _canonical_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True)


def account_registration_work_preimage(env: TxEnvelope, work_nonce: int) -> bytes:
    payload_json = _canonical_json(_payload_without_work(env.payload))
    preimage = [
        ACCOUNT_REGISTRATION_WORK_DOMAIN,
        ACCOUNT_REGISTRATION_WORK_VERSION,
        str(getattr(env, "chain_id", "") or "").strip(),
        str(env.signer or "").strip(),
        int(env.nonce),
        str(getattr(env, "sig_profile", "") or "").strip(),
        getattr(env, "parent", None),
        payload_json,
        int(work_nonce),
    ]
    return _canonical_json(preimage).encode("utf-8")


def account_registration_work_digest(env: TxEnvelope, work_nonce: int) -> bytes:
    return hashlib.sha256(account_registration_work_preimage(env, work_nonce)).digest()


def leading_zero_bits(digest: bytes) -> int:
    total = 0
    for byte in digest:
        if byte == 0:
            total += 8
            continue
        total += 8 - int(byte).bit_length()
        break
    return total


def verify_account_registration_work(state: Json, env: TxEnvelope) -> tuple[bool, str, Json]:
    if str(env.tx_type or "").strip().upper() != "ACCOUNT_REGISTER":
        return True, "", {}

    policy = account_registration_work_policy(state)
    if not policy.valid:
        return (
            False,
            policy.reason or "registration_work_policy_invalid",
            {
                "required": bool(policy.required),
                "difficulty_bits": int(policy.difficulty_bits),
            },
        )
    if not policy.required:
        return True, "", {}

    payload = env.payload if isinstance(env.payload, dict) else {}
    version = str(payload.get("registration_work_version") or "").strip()
    if version != ACCOUNT_REGISTRATION_WORK_VERSION:
        return (
            False,
            "registration_work_version_required",
            {
                "expected": ACCOUNT_REGISTRATION_WORK_VERSION,
            },
        )

    raw_nonce = payload.get("registration_work_nonce")
    if isinstance(raw_nonce, bool):
        return False, "registration_work_nonce_invalid", {}
    try:
        work_nonce = int(raw_nonce)
    except Exception:
        return False, "registration_work_nonce_invalid", {}
    if work_nonce < 0 or work_nonce > ACCOUNT_REGISTRATION_WORK_MAX_NONCE:
        return (
            False,
            "registration_work_nonce_out_of_range",
            {
                "max_nonce": ACCOUNT_REGISTRATION_WORK_MAX_NONCE,
            },
        )

    digest = account_registration_work_digest(env, work_nonce)
    actual_bits = leading_zero_bits(digest)
    if actual_bits < policy.difficulty_bits:
        return (
            False,
            "registration_work_insufficient",
            {
                "required_bits": int(policy.difficulty_bits),
                "actual_bits": int(actual_bits),
            },
        )
    return (
        True,
        "",
        {
            "version": ACCOUNT_REGISTRATION_WORK_VERSION,
            "difficulty_bits": int(policy.difficulty_bits),
            "actual_bits": int(actual_bits),
        },
    )


def account_registration_work_policy_json(state: Json) -> Json:
    policy = account_registration_work_policy(state)
    return {
        "required": bool(policy.required),
        "difficulty_bits": int(policy.difficulty_bits),
        "valid": bool(policy.valid),
        "reason": str(policy.reason or ""),
        "version": ACCOUNT_REGISTRATION_WORK_VERSION,
        "max_nonce": ACCOUNT_REGISTRATION_WORK_MAX_NONCE,
        "production_min_bits": ACCOUNT_REGISTRATION_WORK_PRODUCTION_MIN_BITS,
    }


__all__ = [
    "ACCOUNT_REGISTRATION_WORK_DOMAIN",
    "ACCOUNT_REGISTRATION_WORK_MAX_BITS",
    "ACCOUNT_REGISTRATION_WORK_MAX_NONCE",
    "ACCOUNT_REGISTRATION_WORK_MIN_BITS",
    "ACCOUNT_REGISTRATION_WORK_PRODUCTION_CHAIN_IDS",
    "ACCOUNT_REGISTRATION_WORK_PRODUCTION_MIN_BITS",
    "ACCOUNT_REGISTRATION_WORK_VERSION",
    "AccountRegistrationWorkPolicy",
    "account_registration_work_digest",
    "account_registration_work_policy",
    "account_registration_work_policy_json",
    "account_registration_work_preimage",
    "leading_zero_bits",
    "verify_account_registration_work",
]
