# src/weall/runtime/public_protocol_policy.py
from __future__ import annotations

"""Consensus-visible public-only protocol policy.

WeAll is a public civic protocol.  This module is intentionally dependency-light
so it can run in both admission and deterministic block replay before any domain
applier mutates state.  The policy rejects non-public groups, member-only-readable content, and encrypted/opaque payload fields that would give consensus meaning to content validators cannot inspect.
"""

from dataclasses import dataclass
from typing import Any

Json = dict[str, Any]

PRIVATE_GROUPS_UNSUPPORTED = "PRIVATE_GROUPS_UNSUPPORTED"
ENCRYPTED_PROTOCOL_PAYLOAD_UNSUPPORTED = "ENCRYPTED_PROTOCOL_PAYLOAD_UNSUPPORTED"
GROUP_READ_VISIBILITY_MUST_BE_PUBLIC = "GROUP_READ_VISIBILITY_MUST_BE_PUBLIC"

# These keys are forbidden anywhere inside protocol tx payloads.  Network TLS,
# validator signatures, and local private keys are outside tx payloads and are
# not affected by this policy.
ENCRYPTED_PROTOCOL_KEYS: set[str] = {
    "encrypted_message",
    "encrypted_payload",
    "ciphertext",
    "sealed_payload",
    "recipient_public_key",
    "recipient_encryption_public_jwk",
    "sender_encryption_public_jwk",
    "recipient_encryption_key_id",
    "sender_encryption_key_id",
    "shared_secret",
    "hmac_secret",
    "e2ee",
    "encryption",
    "encryption_scheme",
    "whisper",
}

PRIVATE_GROUP_KEYS: set[str] = {
    "private_group",
    "is_private",
    "member_only_read",
    "member_only_readable",
    "members_only",
    "members_only_read",
    "read_members_only",
    "read_visibility",
    "group_visibility",
    "privacy",
}

PRIVATE_VISIBILITY_VALUES: set[str] = {
    "private",
    "closed",
    "members",
    "member",
    "members_only",
    "members-only",
    "member_only",
    "member-only",
    "member_only_read",
    "member-only-read",
    "member_only_readable",
    "members_only_read",
    "members-only-read",
    "scoped",
    "invite_only",
    "invite-only",
}

PUBLIC_VISIBILITY_VALUES: set[str] = {"", "public", "open", "group"}

PROTOCOL_CONTENT_TX_PREFIXES: tuple[str, ...] = (
    "CONTENT_",
    "GOV_",
    "DISPUTE_",
    "GROUP_",
    "REPUTATION_",
    "VALIDATOR_",
    "ROLE_",
    "POH_",
    "NOTIFICATION_",
    "ACCOUNT_",
)


@dataclass(frozen=True)
class PublicProtocolPolicyViolation:
    code: str
    reason: str
    details: Json


def _norm_key(key: Any) -> str:
    return str(key or "").strip().lower().replace("-", "_").replace(" ", "_")


def _norm_value(value: Any) -> str:
    return str(value or "").strip().lower().replace("-", "_").replace(" ", "_")


def _path(parent: str, key: Any) -> str:
    k = str(key)
    return f"{parent}.{k}" if parent else k


def _payload(env: Any) -> Json:
    if isinstance(env, dict):
        p = env.get("payload")
    else:
        p = getattr(env, "payload", None)
    return p if isinstance(p, dict) else {}


def _tx_type(env: Any) -> str:
    if isinstance(env, dict):
        return str(env.get("tx_type") or "").strip().upper()
    return str(getattr(env, "tx_type", "") or "").strip().upper()


def _walk(value: Any, path: str = "payload"):
    if isinstance(value, dict):
        for key, child in value.items():
            child_path = _path(path, key)
            yield child_path, key, child
            yield from _walk(child, child_path)
    elif isinstance(value, list):
        for idx, child in enumerate(value):
            child_path = f"{path}[{idx}]"
            yield child_path, idx, child
            yield from _walk(child, child_path)


def public_protocol_policy_violation(env: Any) -> PublicProtocolPolicyViolation | None:
    """Return a deterministic violation for a protocol-native tx, if any."""

    t = _tx_type(env)
    p = _payload(env)


    for path, key, value in _walk(p):
        nk = _norm_key(key)
        nv = _norm_value(value) if isinstance(value, (str, bool, int, float)) else ""

        if nk in ENCRYPTED_PROTOCOL_KEYS or "ciphertext" in nk or "encryption" in nk:
            return PublicProtocolPolicyViolation(
                ENCRYPTED_PROTOCOL_PAYLOAD_UNSUPPORTED,
                "encrypted_or_opaque_protocol_payloads_are_unsupported",
                {"tx_type": t, "field": nk, "path": path},
            )

        if nk in PRIVATE_GROUP_KEYS:
            if isinstance(value, bool) and value is True:
                return PublicProtocolPolicyViolation(
                    PRIVATE_GROUPS_UNSUPPORTED,
                    "private_groups_are_unsupported",
                    {"tx_type": t, "field": nk, "path": path},
                )
            if nv in PRIVATE_VISIBILITY_VALUES:
                return PublicProtocolPolicyViolation(
                    GROUP_READ_VISIBILITY_MUST_BE_PUBLIC,
                    "group_read_visibility_must_be_public",
                    {"tx_type": t, "field": nk, "value": nv, "path": path},
                )

        if nk in {"visibility", "read_visibility", "group_visibility", "access", "audience"}:
            if nv in PRIVATE_VISIBILITY_VALUES:
                return PublicProtocolPolicyViolation(
                    GROUP_READ_VISIBILITY_MUST_BE_PUBLIC,
                    "protocol_content_read_visibility_must_be_public",
                    {"tx_type": t, "field": nk, "value": nv, "path": path},
                )

        if isinstance(value, str):
            lowered = value.strip().lower()
            if "-----begin pgp message-----" in lowered or lowered.startswith("age-encryption.org/v1"):
                return PublicProtocolPolicyViolation(
                    ENCRYPTED_PROTOCOL_PAYLOAD_UNSUPPORTED,
                    "armored_encrypted_protocol_payloads_are_unsupported",
                    {"tx_type": t, "field": nk, "path": path},
                )

    return None


def assert_public_protocol_tx(env: Any) -> None:
    violation = public_protocol_policy_violation(env)
    if violation is not None:
        raise ValueError(f"{violation.code}:{violation.reason}:{violation.details}")


__all__ = [
    "PRIVATE_GROUPS_UNSUPPORTED",
    "ENCRYPTED_PROTOCOL_PAYLOAD_UNSUPPORTED",
    "GROUP_READ_VISIBILITY_MUST_BE_PUBLIC",
    "PublicProtocolPolicyViolation",
    "public_protocol_policy_violation",
    "assert_public_protocol_tx",
]
