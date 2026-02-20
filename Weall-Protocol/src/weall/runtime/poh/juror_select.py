from __future__ import annotations

import hashlib
import random
from typing import Any, Dict, List, Tuple

Json = Dict[str, Any]


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

    Seed derived from:
      - state.tip
      - state.height
      - case_id

    Excludes target_account.
    """
    tip = _as_str(state.get("tip")).strip()
    height = _as_int(state.get("height"), 0)

    seed_material = f"{tip}|{height}|{case_id}".encode("utf-8")
    seed = int.from_bytes(hashlib.sha256(seed_material).digest(), "big")

    pool = eligible_tier2_jurors(state=state, min_rep=min_rep)
    pool = [a for a in pool if a != target_account]

    need = int(n_jurors)
    if len(pool) < need:
        raise ValueError(f"insufficient_eligible_jurors: need {need}, have {len(pool)}")

    rng = random.Random(seed)
    rng.shuffle(pool)
    return pool[:need]


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

    Seed is derived from:
      - state.tip (block hash-ish)
      - state.height
      - case_id
    """
    tip = _as_str(state.get("tip")).strip()
    height = _as_int(state.get("height"), 0)

    seed_material = f"{tip}|{height}|{case_id}".encode("utf-8")
    seed = int.from_bytes(hashlib.sha256(seed_material).digest(), "big")

    pool = eligible_tier3_jurors(state=state, min_rep=min_rep)
    pool = [a for a in pool if a != target_account]

    need = int(n_interacting) + int(n_observing)
    if len(pool) < need:
        raise ValueError(
            f"insufficient_eligible_jurors: need {need}, have {len(pool)}"
        )

    rng = random.Random(seed)
    rng.shuffle(pool)

    interacting = pool[: int(n_interacting)]
    observing = pool[int(n_interacting) : need]
    return interacting, observing
