from __future__ import annotations

import hashlib
from typing import Any, Dict, List, Tuple

from weall.runtime.vrf_sig import state_vrf_output

Json = Dict[str, Any]


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
    return hashlib.sha256(f"fallback|{tip}|{height}".encode("utf-8")).hexdigest()


def _score(seed_hex: str, *parts: str) -> str:
    msg = "|".join([seed_hex, *[str(p) for p in parts]])
    return hashlib.sha256(msg.encode("utf-8")).hexdigest()


def _as_dict(x: Any) -> Json:
    return x if isinstance(x, dict) else {}


def _as_str(x: Any) -> str:
    return x if isinstance(x, str) else ""


def _as_float(x: Any, default: float = 0.0) -> float:
    try:
        return float(x)
    except Exception:
        return float(default)


def _as_int(x: Any, default: int = 0) -> int:
    try:
        return int(x)
    except Exception:
        return int(default)


def eligible_tier3_jurors(
    *,
    state: Json,
    min_rep: float = 0.0,
) -> List[str]:
    accounts = state.get("accounts")
    if not isinstance(accounts, dict):
        return []

    out: List[str] = []
    for account_id, rec_any in accounts.items():
        rec = _as_dict(rec_any)
        if bool(rec.get("banned", False)) or bool(rec.get("locked", False)):
            continue
        tier = _as_int(rec.get("poh_tier", 0), 0)
        if tier < 3:
            continue
        rep = _as_float(rec.get("reputation", 0.0), 0.0)
        if rep < float(min_rep):
            continue
        aid = _as_str(account_id).strip()
        if aid:
            out.append(aid)

    # deterministic ordering baseline (before seeded shuffle)
    out.sort()
    return out


def eligible_tier2_jurors(
    *,
    state: Json,
    min_rep: float = 0.0,
) -> List[str]:
    """Eligible jurors for Tier 2 reviews.

    MVP policy: require Tier 3 accounts (stronger trust baseline) and reputation >= min_rep.
    """
    accounts = state.get("accounts")
    if not isinstance(accounts, dict):
        return []

    out: List[str] = []
    for account_id, rec_any in accounts.items():
        rec = _as_dict(rec_any)
        if bool(rec.get("banned", False)) or bool(rec.get("locked", False)):
            continue
        tier = _as_int(rec.get("poh_tier", 0), 0)
        if tier < 3:
            continue
        rep = _as_float(rec.get("reputation", 0.0), 0.0)
        if rep < float(min_rep):
            continue
        aid = _as_str(account_id).strip()
        if aid:
            out.append(aid)

    out.sort()
    return out


def pick_tier2_jurors(
    *,
    state: Json,
    case_id: str,
    target_account: str,
    n_jurors: int = 3,
    min_rep: float = 0.0,
) -> List[str]:
    """Deterministically pick Tier 2 jurors.

    Entropy source:
      - Prefer state.rand.vrf.output (verifiable randomness included by proposer)
      - Else fallback sha256(tip|height)

    Deterministic ranking:
      score = sha256(entropy|"poh2"|case_id|account_id)

    Excludes target_account.
    """

    entropy = _entropy_hex(state=state)

    pool = eligible_tier2_jurors(state=state, min_rep=min_rep)
    pool = [a for a in pool if a != target_account]

    need = int(n_jurors)
    if len(pool) < need:
        raise ValueError(f"insufficient_eligible_jurors: need {need}, have {len(pool)}")

    scored = [(_score(entropy, "poh2", str(case_id), a), a) for a in pool]
    scored.sort(key=lambda t: t[0])
    return [a for _h, a in scored[:need]]


def pick_tier3_jurors(
    *,
    state: Json,
    case_id: str,
    target_account: str,
    n_interacting: int = 3,
    n_observing: int = 7,
    min_rep: float = 0.0,
) -> Tuple[List[str], List[str]]:
    """
    Deterministically pick jurors from eligible Tier 3 accounts.

    Entropy source:
      - Prefer state.rand.vrf.output (verifiable randomness included by proposer)
      - Else fallback sha256(tip|height)

    Deterministic ranking:
      score = sha256(entropy|"poh3"|case_id|account_id)
    """

    entropy = _entropy_hex(state=state)

    pool = eligible_tier3_jurors(state=state, min_rep=min_rep)
    pool = [a for a in pool if a != target_account]

    need = int(n_interacting) + int(n_observing)
    if len(pool) < need:
        raise ValueError(
            f"insufficient_eligible_jurors: need {need}, have {len(pool)}"
        )

    scored = [(_score(entropy, "poh3", str(case_id), a), a) for a in pool]
    scored.sort(key=lambda t: t[0])
    ranked = [a for _h, a in scored]

    interacting = ranked[: int(n_interacting)]
    observing = ranked[int(n_interacting) : need]
    return interacting, observing
