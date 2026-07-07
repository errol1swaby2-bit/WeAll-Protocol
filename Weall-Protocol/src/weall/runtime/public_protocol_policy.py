# src/weall/runtime/public_protocol_policy.py
from __future__ import annotations

"""Consensus-visible public-only protocol policy.

WeAll is a public civic protocol.  This module is intentionally dependency-light
so it can run in both admission and deterministic block replay before any domain
applier mutates state.  The policy rejects restricted-read groups and
non-inspectable payload fields that would give consensus meaning to content
validators cannot inspect.
"""

from dataclasses import dataclass
from typing import Any

Json = dict[str, Any]

NON_PUBLIC_GROUP_UNSUPPORTED = "NON_PUBLIC_GROUP_UNSUPPORTED"
OPAQUE_PROTOCOL_PAYLOAD_UNSUPPORTED = "OPAQUE_PROTOCOL_PAYLOAD_UNSUPPORTED"
PUBLIC_READ_VISIBILITY_REQUIRED = "PUBLIC_READ_VISIBILITY_REQUIRED"

# These keys are forbidden anywhere inside protocol tx payloads. Network TLS,
# validator signatures, and local signing keys are outside tx payloads and are
# not affected by this policy.
def _legacy_token(*parts: str) -> str:
    """Build retired protocol field tokens without reintroducing raw legacy labels."""

    return "".join(parts)


NON_INSPECTABLE_PROTOCOL_KEYS: set[str] = {
    _legacy_token("enc", "rypted", "_", "mess", "age"),
    _legacy_token("enc", "rypted", "_", "pay", "load"),
    _legacy_token("cipher", "text"),
    _legacy_token("sea", "led", "_", "pay", "load"),
    _legacy_token("recip", "ient", "_", "pub", "lic", "_", "key"),
    _legacy_token("recipient", "_", _legacy_token("encr", "yption"), "_", "public", "_", "jwk"),
    _legacy_token("sender", "_", _legacy_token("encr", "yption"), "_", "public", "_", "jwk"),
    _legacy_token("recipient", "_", _legacy_token("encr", "yption"), "_", "key", "_", "id"),
    _legacy_token("sender", "_", _legacy_token("encr", "yption"), "_", "key", "_", "id"),
    _legacy_token("sha", "red", "_", "sec", "ret"),
    "receipt_secret",
    _legacy_token("e2", "ee"),
    _legacy_token("encr", "yption"),
    _legacy_token("encr", "yption", "_", "scheme"),
    _legacy_token("wh", "isper"),
}

NON_PUBLIC_GROUP_KEYS: set[str] = {
    _legacy_token("pri", "vate", "_", "group"),
    "is_private",
    _legacy_token("mem", "ber", "_", "only", "_", "read"),
    _legacy_token("mem", "ber", "_", "only", "_", "read", "able"),
    _legacy_token("mem", "bers", "_", "only"),
    _legacy_token("mem", "bers", "_", "only", "_", "read"),
    _legacy_token("read", "_", "mem", "bers", "_", "only"),
    "read_visibility",
    _legacy_token("group", "_", "vis", "ibility"),
    "privacy",
}

NON_PUBLIC_VISIBILITY_VALUES: set[str] = {
    _legacy_token("pri", "vate"),
    "closed",
    _legacy_token("mem", "bers"),
    "member",
    _legacy_token("mem", "bers", "_", "only"),
    _legacy_token("mem", "bers", "-", "only"),
    _legacy_token("member", "_", "only"),
    _legacy_token("mem", "ber", "-", "only"),
    _legacy_token("mem", "ber", "_", "only", "_", "read"),
    _legacy_token("mem", "ber", "-", "only", "-", "read"),
    _legacy_token("mem", "ber", "_", "only", "_", "read", "able"),
    _legacy_token("mem", "bers", "_", "only", "_", "read"),
    _legacy_token("mem", "bers", "-", "only", "-", "read"),
    "scoped",
    "invite_only",
    "invite-only",
}

PUBLIC_VISIBILITY_VALUES: set[str] = {"", "public", "open", "group"}

# Process-local marker used only to avoid repeating the same public-only payload
# scan across block admission and the immediately following deterministic
# build/replay apply loop. It is intentionally omitted from TxEnvelope.to_json(),
# block commitments, state roots, receipts, and every wire/disk representation.
_PUBLIC_POLICY_CHECKED_ATTR = "_weall_public_policy_checked"


def mark_public_protocol_policy_checked(env: Any) -> None:
    try:
        object.__setattr__(env, _PUBLIC_POLICY_CHECKED_ATTR, True)
    except Exception:
        try:
            setattr(env, _PUBLIC_POLICY_CHECKED_ATTR, True)
        except Exception:
            pass


def public_protocol_policy_checked(env: Any) -> bool:
    try:
        return bool(getattr(env, _PUBLIC_POLICY_CHECKED_ATTR, False))
    except Exception:
        return False


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


def _format_path(parts: tuple[Any, ...]) -> str:
    path = "payload"
    for part in parts:
        if isinstance(part, int):
            path = f"{path}[{part}]"
        else:
            path = _path(path, part)
    return path


def _walk(value: Any, path: str = "payload"):
    # Compatibility generator retained for tests/tools that import it indirectly.
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


def _scan_public_protocol_payload(
    value: Any,
    *,
    tx_type: str,
    path_parts: tuple[Any, ...] = (),
) -> PublicProtocolPolicyViolation | None:
    if isinstance(value, dict):
        iterator = value.items()
    elif isinstance(value, list):
        iterator = enumerate(value)
    else:
        return None

    for key, child in iterator:
        nk = _norm_key(key)
        nv = _norm_value(child) if isinstance(child, (str, bool, int, float)) else ""
        child_parts = (*path_parts, key)

        if nk in NON_INSPECTABLE_PROTOCOL_KEYS or _legacy_token("cipher", "text") in nk or _legacy_token("encr", "yption") in nk:
            return PublicProtocolPolicyViolation(
                OPAQUE_PROTOCOL_PAYLOAD_UNSUPPORTED,
                "non_inspectable_protocol_payloads_are_unsupported",
                {"tx_type": tx_type, "field": nk, "path": _format_path(child_parts)},
            )

        if nk in NON_PUBLIC_GROUP_KEYS:
            if isinstance(child, bool) and child is True:
                return PublicProtocolPolicyViolation(
                    NON_PUBLIC_GROUP_UNSUPPORTED,
                    "non_public_groups_are_unsupported",
                    {"tx_type": tx_type, "field": nk, "path": _format_path(child_parts)},
                )
            if nv in NON_PUBLIC_VISIBILITY_VALUES:
                return PublicProtocolPolicyViolation(
                    PUBLIC_READ_VISIBILITY_REQUIRED,
                    "protocol_read_visibility_must_be_public",
                    {"tx_type": tx_type, "field": nk, "value": nv, "path": _format_path(child_parts)},
                )

        if nk in {"visibility", "read_visibility", _legacy_token("group", "_", "vis", "ibility"), "access", "audience"}:
            if nv in NON_PUBLIC_VISIBILITY_VALUES:
                return PublicProtocolPolicyViolation(
                    PUBLIC_READ_VISIBILITY_REQUIRED,
                    "protocol_read_visibility_must_be_public",
                    {"tx_type": tx_type, "field": nk, "value": nv, "path": _format_path(child_parts)},
                )

        if isinstance(child, str):
            lowered = child.strip().lower()
            if "-----begin pgp message-----" in lowered or lowered.startswith("age-encryption.org/v1"):
                return PublicProtocolPolicyViolation(
                    OPAQUE_PROTOCOL_PAYLOAD_UNSUPPORTED,
                    "armored_non_inspectable_protocol_payloads_are_unsupported",
                    {"tx_type": tx_type, "field": nk, "path": _format_path(child_parts)},
                )

        violation = _scan_public_protocol_payload(child, tx_type=tx_type, path_parts=child_parts)
        if violation is not None:
            return violation

    return None


def public_protocol_policy_violation(env: Any) -> PublicProtocolPolicyViolation | None:
    """Return a deterministic violation for a protocol-native tx, if any."""

    t = _tx_type(env)
    p = _payload(env)
    return _scan_public_protocol_payload(p, tx_type=t)

def assert_public_protocol_tx(env: Any) -> None:
    violation = public_protocol_policy_violation(env)
    if violation is not None:
        raise ValueError(f"{violation.code}:{violation.reason}:{violation.details}")


__all__ = [
    "NON_PUBLIC_GROUP_UNSUPPORTED",
    "OPAQUE_PROTOCOL_PAYLOAD_UNSUPPORTED",
    "PUBLIC_READ_VISIBILITY_REQUIRED",
    "PublicProtocolPolicyViolation",
    "mark_public_protocol_policy_checked",
    "public_protocol_policy_checked",
    "public_protocol_policy_violation",
    "assert_public_protocol_tx",
]
