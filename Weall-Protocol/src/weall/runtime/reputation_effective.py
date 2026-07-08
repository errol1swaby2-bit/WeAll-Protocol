from __future__ import annotations

"""Effective public reputation totals used by readiness/status gates.

This read model deliberately treats the scalar account reputation and the
canonical event-sourced public aggregate as compatible sources during the
v1.5 hardening transition.  The effective value is the higher deterministic
public value, so freshly finalized Tier-2 / PoH events represented in the
Reputation Matrix are not hidden by a stale account.reputation_milli field.
"""

from typing import Any, Mapping

from weall.runtime.reputation_units import account_reputation_units

Json = dict[str, Any]


def _as_dict(value: Any) -> Json:
    return value if isinstance(value, dict) else {}


def _as_str(value: Any) -> str:
    try:
        return str(value or "").strip()
    except Exception:
        return ""


def account_record_for_reputation(state: Mapping[str, Any], account_id: str) -> Json:
    accounts = _as_dict(state.get("accounts"))
    clean = _as_str(account_id)
    base = clean[1:] if clean.startswith("@") else clean
    for key in (clean, base, f"@{base}" if base else ""):
        rec = accounts.get(key)
        if isinstance(rec, dict):
            return rec
    return {}


def effective_account_reputation_units(state: Mapping[str, Any], account_id: str, *, default: int = 0) -> int:
    acct = account_record_for_reputation(state, account_id)
    scalar = account_reputation_units(acct, default=default) if acct else int(default)
    aggregate = 0
    strongest_dimension = 0
    try:
        from weall.runtime.reputation_matrix import derive_reputation_matrix

        matrix = derive_reputation_matrix(dict(state), account_id, reveal_restricted=False, include_events=False)
        aggregate = int(matrix.get("aggregate_public_score_milli") or 0)
        dimensions = _as_dict(matrix.get("dimensions")) or _as_dict(matrix.get("canonical_dimensions"))
        for dim in dimensions.values():
            if isinstance(dim, dict):
                strongest_dimension = max(strongest_dimension, int(dim.get("score_milli") or 0))
    except Exception:
        aggregate = 0
        strongest_dimension = 0
    return max(int(default), int(scalar), int(aggregate), int(strongest_dimension))
