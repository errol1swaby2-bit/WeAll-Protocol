from __future__ import annotations

from typing import Any

from weall.runtime.bft_hotstuff import BFT_MIN_VALIDATORS, normalize_validators

Json = dict[str, Any]


def _as_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except Exception:
        return int(default)


def _as_str(value: Any) -> str:
    try:
        return str(value)
    except Exception:
        return ""


def active_validator_count(state: Json) -> int:
    candidates: list[str] = []
    roles = state.get("roles")
    if isinstance(roles, dict):
        validators = roles.get("validators")
        if isinstance(validators, dict) and isinstance(validators.get("active_set"), list):
            candidates = [_as_str(item).strip() for item in validators.get("active_set") or []]

    if not candidates:
        consensus = state.get("consensus")
        if isinstance(consensus, dict):
            validator_set = consensus.get("validator_set")
            if isinstance(validator_set, dict) and isinstance(validator_set.get("active_set"), list):
                candidates = [_as_str(item).strip() for item in validator_set.get("active_set") or []]

    return len(normalize_validators([item for item in candidates if item]))


def poh_bootstrap_quorum_allowed(state: Json, *, height: int | None = None) -> bool:
    params = state.get("params")
    params = params if isinstance(params, dict) else {}
    mode = _as_str(params.get("poh_bootstrap_mode") or "").strip().lower()
    if mode not in {"allowlist", "bootstrap", "genesis", "open"}:
        return False

    current_height = _as_int(state.get("height"), 0) if height is None else int(height)
    expires_height = _as_int(
        params.get("bootstrap_expires_height")
        or params.get("poh_bootstrap_quorum_until_height")
        or params.get("poh_live_partial_until_height")
        or 0,
        0,
    )
    if expires_height > 0 and int(current_height) > int(expires_height):
        return False

    return active_validator_count(state) < int(BFT_MIN_VALIDATORS)


def adaptive_bootstrap_review_policy(
    state: Json,
    *,
    configured_jurors: int,
    configured_min_reviews: int,
    configured_approval_threshold: int,
    configured_rejection_threshold: int,
    height: int | None = None,
) -> Json:
    configured_jurors = max(1, int(configured_jurors))
    configured_min_reviews = max(1, int(configured_min_reviews))
    configured_approval_threshold = max(1, int(configured_approval_threshold))
    configured_rejection_threshold = max(1, int(configured_rejection_threshold))

    if not poh_bootstrap_quorum_allowed(state, height=height):
        assigned = configured_jurors
        minimum = configured_min_reviews
    else:
        validator_count = active_validator_count(state)
        assigned = min(configured_jurors, max(1, validator_count))
        minimum = min(configured_min_reviews, assigned)

    approval = min(configured_approval_threshold, minimum)
    rejection = min(configured_rejection_threshold, minimum)
    return {
        "assigned_jurors": int(assigned),
        "minimum_reviews": int(minimum),
        "approval_threshold": int(approval),
        "rejection_threshold": int(rejection),
        "bootstrap_adaptive": bool(assigned != configured_jurors or minimum != configured_min_reviews),
        "active_validators": int(active_validator_count(state)),
        "bft_min_validators": int(BFT_MIN_VALIDATORS),
    }


__all__ = [
    "active_validator_count",
    "adaptive_bootstrap_review_policy",
    "poh_bootstrap_quorum_allowed",
]
