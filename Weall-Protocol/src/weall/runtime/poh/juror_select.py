from __future__ import annotations

import hashlib
from typing import Any

from weall.runtime.poh.live_quorum import MAX_LIVE_JURORS, live_active_reviewer_count

from weall.runtime.reputation_units import account_reputation_units, threshold_to_units
from weall.runtime.vrf_sig import state_vrf_output

Json = dict[str, Any]


def _entropy_hex(*, state: Json) -> str:
    """Return entropy for deterministic selection.

    Prefer the latest VRF output stored at state["rand"]["vrf"]["output"].
    Fall back to sha256(tip|height) if VRF is unavailable.
    """

    out = state_vrf_output(state)
    if isinstance(out, str) and out:
        return out

    tip = _as_str(state.get("tip")).strip()
    height = _as_int(state.get("height"), 0)
    return hashlib.sha256(f"fallback|{tip}|{height}".encode()).hexdigest()


def _score(seed_hex: str, *parts: str) -> str:
    msg = "|".join([seed_hex, *[str(p) for p in parts]])
    return hashlib.sha256(msg.encode("utf-8")).hexdigest()


def _as_dict(x: Any) -> Json:
    return x if isinstance(x, dict) else {}


def _as_str(x: Any) -> str:
    return x if isinstance(x, str) else ""


def _as_int(x: Any, default: int = 0) -> int:
    try:
        return int(x)
    except Exception:
        return int(default)


def _min_rep_units(*, min_rep_units: int | None = None, min_rep: Any = 0) -> int:
    """Normalize legacy float/string thresholds to integer reputation units.

    Consensus/policy call sites should pass ``min_rep_units`` directly. ``min_rep`` is
    preserved only as a compatibility lane for older callers and tests.
    """

    if min_rep_units is not None:
        try:
            return max(0, int(min_rep_units))
        except Exception:
            return 0
    return max(0, threshold_to_units(min_rep, default=0))




def _identity_variants(value: Any) -> list[str]:
    s = str(value or "").strip()
    if not s:
        return []
    base = s[1:] if s.startswith("@") else s
    out: list[str] = []
    seen: set[str] = set()
    for candidate in (s, base, f"@{base}" if base else ""):
        c = str(candidate or "").strip()
        if not c or c in seen:
            continue
        seen.add(c)
        out.append(c)
    return out


def _matches_identity_collection(account_id: str, values: Any) -> bool:
    variants = set(_identity_variants(account_id))
    for value in values or []:
        if variants.intersection(_identity_variants(value)):
            return True
    return False


def _truthy(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return value != 0
    if isinstance(value, str):
        return value.strip().lower() in {"1", "true", "yes", "on", "active", "enabled"}
    return False


def _record_blocked(rec: Any) -> bool:
    if not isinstance(rec, dict):
        return False
    for key in ("banned", "blocked", "disabled", "removed", "replaced", "revoked", "suspended"):
        if _truthy(rec.get(key)):
            return True
    status = str(rec.get("status") or "").strip().lower()
    return status in {
        "banned",
        "blocked",
        "declined",
        "disabled",
        "inactive",
        "removed",
        "replaced",
        "retired",
        "revoked",
        "suspended",
    }


def _record_active(rec: Any) -> bool:
    if not isinstance(rec, dict):
        return False
    if _record_blocked(rec):
        return False
    if _truthy(rec.get("active")) or _truthy(rec.get("activated")) or _truthy(rec.get("enabled")):
        return True
    status = str(rec.get("status") or "").strip().lower()
    return status in {"active", "activated", "enabled", "juror", "live"}


def _role_record_for_identity(mapping: Json, account_id: str) -> Json:
    for variant in _identity_variants(account_id):
        rec = mapping.get(variant)
        if isinstance(rec, dict):
            return rec
    return {}


def _active_juror_role(state: Json, account_id: str) -> bool:
    roles = _as_dict(state.get("roles"))
    jurors = _as_dict(roles.get("jurors"))
    by_id = _as_dict(jurors.get("by_id"))
    rec = _role_record_for_identity(by_id, account_id)
    if rec and _record_blocked(rec):
        return False
    if _matches_identity_collection(account_id, jurors.get("active_set", [])):
        return True
    return _record_active(rec)


def _blocked_juror_role(state: Json, account_id: str) -> bool:
    roles = _as_dict(state.get("roles"))
    jurors = _as_dict(roles.get("jurors"))
    by_id = _as_dict(jurors.get("by_id"))
    rec = _role_record_for_identity(by_id, account_id)
    return bool(rec) and _record_blocked(rec)


def _case_scoped_juror_without_role_allowed(state: Json) -> bool:
    params = _as_dict(state.get("params"))
    for key in (
        "allow_case_scoped_juror_without_role",
        "poh_allow_case_scoped_juror_without_role",
        "bootstrap_allow_case_scoped_juror_without_role",
    ):
        if _truthy(params.get(key)):
            return True
    return False


def _juror_role_required_for_assignment(state: Json, *, allow_roleless_bootstrap: bool = False) -> bool:
    # Assignment must mirror the Juror admission gate.  The only exception is an
    # explicit chain-state bootstrap compatibility flag used by controlled
    # genesis/devnet phases before the active Juror role set exists.
    return not (bool(allow_roleless_bootstrap) or _case_scoped_juror_without_role_allowed(state))


def eligible_live_jurors(
    *,
    state: Json,
    min_rep_units: int | None = None,
    min_rep: Any = 0,
    allow_roleless_bootstrap: bool = False,
) -> list[str]:
    accounts = state.get("accounts")
    if not isinstance(accounts, dict):
        return []

    required_units = _min_rep_units(min_rep_units=min_rep_units, min_rep=min_rep)
    out: list[str] = []
    for account_id, rec_any in accounts.items():
        rec = _as_dict(rec_any)
        if bool(rec.get("banned", False)) or bool(rec.get("locked", False)):
            continue
        tier = _as_int(rec.get("poh_tier", 0), 0)
        if tier < 2:
            continue
        aid = _as_str(account_id).strip()
        if not aid:
            continue
        if _blocked_juror_role(state, aid):
            continue
        if _juror_role_required_for_assignment(state, allow_roleless_bootstrap=allow_roleless_bootstrap) and not _active_juror_role(state, aid):
            continue
        rep_units = account_reputation_units(rec, default=0)
        if rep_units < required_units:
            continue
        out.append(aid)

    # deterministic ordering baseline (before seeded shuffle)
    out.sort()
    return out


def eligible_tier2_jurors(
    *,
    state: Json,
    min_rep_units: int | None = None,
    min_rep: Any = 0,
    allow_roleless_bootstrap: bool = False,
) -> list[str]:
    """Eligible jurors for Tier 2 reviews.

    MVP policy after v2.1 migration: require Tier 2 / Live Verified Human accounts and reputation >= threshold.
    """
    accounts = state.get("accounts")
    if not isinstance(accounts, dict):
        return []

    required_units = _min_rep_units(min_rep_units=min_rep_units, min_rep=min_rep)
    out: list[str] = []
    for account_id, rec_any in accounts.items():
        rec = _as_dict(rec_any)
        if bool(rec.get("banned", False)) or bool(rec.get("locked", False)):
            continue
        tier = _as_int(rec.get("poh_tier", 0), 0)
        if tier < 2:
            continue
        aid = _as_str(account_id).strip()
        if not aid:
            continue
        if _blocked_juror_role(state, aid):
            continue
        if _juror_role_required_for_assignment(state, allow_roleless_bootstrap=allow_roleless_bootstrap) and not _active_juror_role(state, aid):
            continue
        rep_units = account_reputation_units(rec, default=0)
        if rep_units < required_units:
            continue
        out.append(aid)

    out.sort()
    return out


def pick_tier2_jurors(
    *,
    state: Json,
    case_id: str,
    target_account: str,
    n_jurors: int = 3,
    min_rep_units: int | None = None,
    min_rep: Any = 0,
) -> list[str]:
    """Deterministically pick Tier 2 jurors.

    Entropy source:
      - Prefer state.rand.vrf.output (verifiable randomness included by proposer)
      - Else fallback sha256(tip|height)

    Deterministic ranking:
      score = sha256(entropy|"poh2"|case_id|account_id)

    Excludes target_account.
    """

    entropy = _entropy_hex(state=state)

    pool = eligible_tier2_jurors(
        state=state,
        min_rep_units=min_rep_units,
        min_rep=min_rep,
    )
    pool = [a for a in pool if a != target_account]

    need = int(n_jurors)
    if len(pool) < need:
        raise ValueError(f"insufficient_eligible_jurors: need {need}, have {len(pool)}")

    scored = [(_score(entropy, "poh2", str(case_id), a), a) for a in pool]
    scored.sort(key=lambda t: t[0])
    return [a for _h, a in scored[:need]]


def pick_async_jurors(
    *,
    state: Json,
    case_id: str,
    target_account: str,
    n_jurors: int = 3,
    min_rep_units: int | None = None,
    min_rep: Any = 0,
    allow_partial: bool = False,
    allow_roleless_bootstrap: bool = False,
) -> list[str]:
    """Deterministically pick jurors for native async Tier-1 review.

    Native async Tier 1 is reviewed by Live Verified Human accounts.  The
    deterministic ranking uses a dedicated domain separator so async review
    assignments cannot silently drift with legacy Tier-2 or live assignment.
    """

    entropy = _entropy_hex(state=state)
    pool = eligible_live_jurors(
        state=state,
        min_rep_units=min_rep_units,
        min_rep=min_rep,
        allow_roleless_bootstrap=bool(allow_roleless_bootstrap),
    )
    pool = [a for a in pool if a != target_account]

    need = int(n_jurors)
    if len(pool) < need and not bool(allow_partial):
        raise ValueError(f"insufficient_eligible_jurors: need {need}, have {len(pool)}")
    need = min(need, len(pool)) if bool(allow_partial) else need
    if need <= 0:
        raise ValueError("insufficient_eligible_jurors: need at least 1, have 0")

    scored = [(_score(entropy, "pohasync", str(case_id), a), a) for a in pool]
    scored.sort(key=lambda t: t[0])
    return [a for _h, a in scored[:need]]


def pick_live_jurors(
    *,
    state: Json,
    case_id: str,
    target_account: str,
    n_interacting: int = 3,
    n_observing: int = 7,
    min_rep_units: int | None = None,
    min_rep: Any = 0,
    allow_partial: bool = False,
) -> tuple[list[str], list[str]]:
    """Deterministically pick Live PoH jurors.

    Production posture:
      - max 10 total jurors
      - up to 3 active/interacting reviewers
      - up to 7 watching/observing jurors
      - when allow_partial=True, bootstrap uses the available eligible pool
        instead of failing until all 10 seats exist.

    Entropy source:
      - Prefer state.rand.vrf.output (verifiable randomness included by proposer)
      - Else fallback sha256(tip|height)

    Deterministic ranking:
      score = sha256(entropy|"poh3"|case_id|account_id)
    """

    entropy = _entropy_hex(state=state)

    pool = eligible_live_jurors(
        state=state,
        min_rep_units=min_rep_units,
        min_rep=min_rep,
        allow_roleless_bootstrap=bool(allow_partial),
    )
    pool = [a for a in pool if a != target_account]

    configured_need = min(MAX_LIVE_JURORS, max(1, int(n_interacting) + int(n_observing)))
    if len(pool) < configured_need and not bool(allow_partial):
        raise ValueError(f"insufficient_eligible_jurors: need {configured_need}, have {len(pool)}")
    selected_count = min(configured_need, len(pool)) if bool(allow_partial) else configured_need
    if selected_count <= 0:
        raise ValueError("insufficient_eligible_jurors: need at least 1, have 0")

    scored = [(_score(entropy, "poh3", str(case_id), a), a) for a in pool]
    scored.sort(key=lambda t: t[0])
    ranked = [a for _h, a in scored[:selected_count]]

    active_count = live_active_reviewer_count(selected_count)
    interacting = ranked[:active_count]
    observing = ranked[active_count:selected_count]
    return interacting, observing
