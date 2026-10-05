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

# A15-F003 production scarcity policy. "Nonzero" work alone is not a lifetime
# bound: an attacker can keep paying it forever and grow permanent root-visible
# state without limit. Current production/public-testnet semantics therefore use
# two independent controls:
#   1. identity/payload-bound registration work with a reviewed 16-bit floor;
#   2. a hard 10,000-record production account ceiling for this protocol version.
#
# The ceiling intentionally applies to all root-visible account records, including
# bootstrap/system records. A future protocol version may raise or replace it only
# after a separately reviewed state-scaling design and evidence refresh.
ACCOUNT_REGISTRATION_WORK_PRODUCTION_MIN_BITS = 16
ACCOUNT_REGISTRATION_PRODUCTION_MAX_ACCOUNTS = 10_000
ACCOUNT_REGISTRATION_WORK_PRODUCTION_CHAIN_IDS = frozenset({"weall-prod", "weall-testnet-v1"})


@dataclass(frozen=True)
class AccountRegistrationWorkPolicy:
    required: bool
    difficulty_bits: int
    max_accounts: int = 0
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


def _account_limit_policy(params: Json, *, production_chain: bool) -> tuple[int, str]:
    raw = params.get("account_registration_max_accounts")
    if raw is None:
        return (ACCOUNT_REGISTRATION_PRODUCTION_MAX_ACCOUNTS, "") if production_chain else (0, "")
    if isinstance(raw, bool):
        return 0, "account_registration_max_accounts_invalid"
    try:
        limit = int(raw)
    except Exception:
        return 0, "account_registration_max_accounts_invalid"
    if limit < 0:
        return limit, "account_registration_max_accounts_invalid"
    if production_chain:
        if limit <= 0:
            return limit, "account_registration_max_accounts_required"
        if limit > ACCOUNT_REGISTRATION_PRODUCTION_MAX_ACCOUNTS:
            return limit, "account_registration_max_accounts_above_reviewed_ceiling"
    return limit, ""


def account_registration_work_policy(state: Json) -> AccountRegistrationWorkPolicy:
    params = _as_params(state)
    chain_id = str(state.get("chain_id") or "").strip() if isinstance(state, dict) else ""
    production_chain = chain_id in ACCOUNT_REGISTRATION_WORK_PRODUCTION_CHAIN_IDS

    max_accounts, max_accounts_reason = _account_limit_policy(
        params,
        production_chain=production_chain,
    )
    if max_accounts_reason:
        return AccountRegistrationWorkPolicy(
            required=True if production_chain else False,
            difficulty_bits=0,
            max_accounts=max_accounts,
            valid=False,
            reason=max_accounts_reason,
        )

    required, required_valid = _policy_bool(params.get("account_registration_work_required"))
    if not required_valid:
        return AccountRegistrationWorkPolicy(
            required=True,
            difficulty_bits=0,
            max_accounts=max_accounts,
            valid=False,
            reason="registration_work_required_policy_invalid",
        )
    if production_chain and not required:
        return AccountRegistrationWorkPolicy(
            required=True,
            difficulty_bits=0,
            max_accounts=max_accounts,
            valid=False,
            reason="registration_work_required_in_production",
        )
    if not required:
        return AccountRegistrationWorkPolicy(
            required=False,
            difficulty_bits=0,
            max_accounts=max_accounts,
        )

    raw_bits = params.get("account_registration_work_difficulty_bits")
    if isinstance(raw_bits, bool):
        return AccountRegistrationWorkPolicy(
            required=True,
            difficulty_bits=0,
            max_accounts=max_accounts,
            valid=False,
            reason="registration_work_difficulty_invalid",
        )
    try:
        bits = int(raw_bits)
    except Exception:
        return AccountRegistrationWorkPolicy(
            required=True,
            difficulty_bits=0,
            max_accounts=max_accounts,
            valid=False,
            reason="registration_work_difficulty_invalid",
        )
    if bits < ACCOUNT_REGISTRATION_WORK_MIN_BITS or bits > ACCOUNT_REGISTRATION_WORK_MAX_BITS:
        return AccountRegistrationWorkPolicy(
            required=True,
            difficulty_bits=bits,
            max_accounts=max_accounts,
            valid=False,
            reason="registration_work_difficulty_out_of_range",
        )

    if production_chain and bits < ACCOUNT_REGISTRATION_WORK_PRODUCTION_MIN_BITS:
        return AccountRegistrationWorkPolicy(
            required=True,
            difficulty_bits=bits,
            max_accounts=max_accounts,
            valid=False,
            reason="registration_work_difficulty_below_production_minimum",
        )

    return AccountRegistrationWorkPolicy(
        required=True,
        difficulty_bits=bits,
        max_accounts=max_accounts,
    )


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
                "max_accounts": int(policy.max_accounts),
            },
        )

    accounts_any = state.get("accounts") if isinstance(state, dict) else None
    if policy.max_accounts > 0 and not isinstance(accounts_any, dict):
        return False, "account_registry_invalid", {}
    accounts = accounts_any if isinstance(accounts_any, dict) else {}
    signer = str(env.signer or "").strip()
    if policy.max_accounts > 0 and signer not in accounts and len(accounts) >= policy.max_accounts:
        return (
            False,
            "account_registration_capacity_exhausted",
            {
                "current_accounts": len(accounts),
                "max_accounts": int(policy.max_accounts),
            },
        )

    if not policy.required:
        return (
            True,
            "",
            {
                "max_accounts": int(policy.max_accounts),
                "current_accounts": len(accounts),
            },
        )

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
            "max_accounts": int(policy.max_accounts),
            "current_accounts": len(accounts),
        },
    )


def account_registration_work_policy_json(state: Json) -> Json:
    policy = account_registration_work_policy(state)
    accounts = state.get("accounts") if isinstance(state, dict) else None
    current_accounts = len(accounts) if isinstance(accounts, dict) else None
    return {
        "required": bool(policy.required),
        "difficulty_bits": int(policy.difficulty_bits),
        "max_accounts": int(policy.max_accounts),
        "current_accounts": current_accounts,
        "valid": bool(policy.valid),
        "reason": str(policy.reason or ""),
        "version": ACCOUNT_REGISTRATION_WORK_VERSION,
        "max_nonce": ACCOUNT_REGISTRATION_WORK_MAX_NONCE,
        "production_min_bits": ACCOUNT_REGISTRATION_WORK_PRODUCTION_MIN_BITS,
        "production_max_accounts": ACCOUNT_REGISTRATION_PRODUCTION_MAX_ACCOUNTS,
    }


__all__ = [
    "ACCOUNT_REGISTRATION_PRODUCTION_MAX_ACCOUNTS",
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
