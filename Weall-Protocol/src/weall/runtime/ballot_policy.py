from __future__ import annotations

from typing import Any

Json = dict[str, Any]

LAUNCH_GATED_BALLOT_PROFILE = "UNASSIGNED_LAUNCH_GATED"
CONTROLLED_TESTNET_BALLOT_PROFILE = "controlled-testnet-aggregate-v1"

_STRICT_MODES = frozenset(
    {
        "controlled-testnet",
        "controlled_testnet",
        "testnet-controlled",
        "public-testnet",
        "public_testnet",
        "mainnet",
        "production",
        "prod",
    }
)
_PUBLIC_MODES = frozenset({"public-testnet", "public_testnet", "mainnet", "production", "prod"})


def _as_dict(value: Any) -> Json:
    return value if isinstance(value, dict) else {}


def _as_str(value: Any) -> str:
    return str(value).strip() if value is not None else ""


def _as_bool(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    return _as_str(value).lower() in {"1", "true", "yes", "on", "enabled", "active"}


def chain_mode(state: Json) -> str:
    params = _as_dict(state.get("params"))
    return _as_str(
        params.get("mode")
        or params.get("chain_mode")
        or params.get("profile")
        or state.get("mode")
        or state.get("profile")
    ).lower()


def strict_civic_governance_enabled(state: Json) -> bool:
    params = _as_dict(state.get("params"))
    explicit = params.get("m3_civic_governance_strict")
    if explicit is not None:
        return _as_bool(explicit)
    return chain_mode(state) in _STRICT_MODES


def ballot_profile_record(state: Json) -> Json:
    params = _as_dict(state.get("params"))
    raw = state.get("ballot_profile")
    if not isinstance(raw, dict):
        raw = params.get("ballot_profile")
    rec = dict(raw) if isinstance(raw, dict) else {}

    profile_id = _as_str(
        rec.get("profile_id")
        or rec.get("id")
        or params.get("ballot_profile_id")
        or params.get("mainnet_ballot_profile")
        or LAUNCH_GATED_BALLOT_PROFILE
    )
    active = rec.get("active")
    if active is None:
        active = params.get("ballot_profile_active")

    return {
        **rec,
        "profile_id": profile_id,
        "active": _as_bool(active),
        "mode": chain_mode(state),
    }


def _public_activation_receipt_matches(state: Json, profile_id: str, mode: str) -> bool:
    receipts = state.get("ballot_profile_activation_receipts")
    if not isinstance(receipts, list):
        return False
    for item in receipts:
        if not isinstance(item, dict):
            continue
        if _as_str(item.get("profile_id") or item.get("id")) != profile_id:
            continue
        if _as_str(item.get("status") or "active").lower() not in {"active", "activated"}:
            continue
        if not _as_str(item.get("profile_hash") or item.get("digest")):
            continue
        allowed_modes = item.get("allowed_modes")
        if isinstance(allowed_modes, list) and mode not in {
            _as_str(x).lower() for x in allowed_modes
        }:
            continue
        if mode in _PUBLIC_MODES and not _as_bool(item.get("independent_review_complete")):
            continue
        return True
    return False


def ballot_profile_status(state: Json) -> Json:
    strict = strict_civic_governance_enabled(state)
    rec = ballot_profile_record(state)
    profile_id = _as_str(rec.get("profile_id")) or LAUNCH_GATED_BALLOT_PROFILE
    mode = _as_str(rec.get("mode")).lower()

    if not strict:
        return {
            **rec,
            "strict": False,
            "active": True,
            "reason": "legacy_or_local_profile",
        }

    if profile_id == LAUNCH_GATED_BALLOT_PROFILE:
        return {
            **rec,
            "strict": True,
            "active": False,
            "reason": "launch_gated_profile_unassigned",
        }

    if mode in _PUBLIC_MODES:
        active = bool(rec.get("active")) and _public_activation_receipt_matches(
            state, profile_id, mode
        )
        return {
            **rec,
            "strict": True,
            "active": active,
            "reason": "active_public_profile"
            if active
            else "public_profile_activation_receipt_missing",
        }

    # Controlled-testnet use is intentionally bounded to aggregate-only public
    # reads. It is not a claim that coercion-resistant sealed-ballot cryptography
    # is production ready.
    active = bool(rec.get("active")) and profile_id == CONTROLLED_TESTNET_BALLOT_PROFILE
    return {
        **rec,
        "strict": True,
        "active": active,
        "reason": "active_controlled_testnet_profile"
        if active
        else "controlled_testnet_profile_inactive",
    }


def ballot_profile_is_active(state: Json) -> bool:
    return bool(ballot_profile_status(state).get("active"))


def ballot_context_commitment_payload(
    *,
    chain_id: str,
    subject_id: str,
    ballot_class: str,
    round_no: int,
    electorate_commitment: str,
    option_commitment: str,
    open_height: int,
    close_height: int,
    profile_id: str,
) -> Json:
    return {
        "domain": "weall.ballot.context.v1",
        "chain_id": _as_str(chain_id),
        "subject_id": _as_str(subject_id),
        "ballot_class": _as_str(ballot_class),
        "round": int(round_no),
        "electorate_commitment": _as_str(electorate_commitment),
        "option_commitment": _as_str(option_commitment),
        "open_height": int(open_height),
        "close_height": int(close_height),
        "profile_id": _as_str(profile_id),
    }
