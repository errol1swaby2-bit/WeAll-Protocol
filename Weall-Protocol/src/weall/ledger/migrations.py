# src/weall/ledger/migrations.py
from __future__ import annotations

from typing import Any, Dict, Callable

Json = Dict[str, Any]

# Increment this when you add a new migration step.
CURRENT_STATE_VERSION = 1


def _as_int(v: Any, default: int = 0) -> int:
    try:
        if isinstance(v, bool):
            return default
        return int(v)
    except Exception:
        return default


def _as_str(v: Any) -> str:
    try:
        return str(v) if v is not None else ""
    except Exception:
        return ""


def _ensure_dict(root: Json, key: str) -> Json:
    v = root.get(key)
    if not isinstance(v, dict):
        v = {}
        root[key] = v
    return v


def _ensure_int(root: Json, key: str, default: int = 0) -> int:
    if key not in root:
        root[key] = int(default)
        return int(default)
    x = _as_int(root.get(key), default)
    root[key] = int(x)
    return int(x)


def _ensure_str(root: Json, key: str, default: str = "") -> str:
    if key not in root:
        root[key] = str(default)
        return str(default)
    s = _as_str(root.get(key))
    root[key] = s
    return s


def _ensure_bool(root: Json, key: str, default: bool = False) -> bool:
    if key not in root:
        root[key] = bool(default)
        return bool(default)
    v = root.get(key)
    if isinstance(v, bool):
        return v
    if isinstance(v, (int, float)) and v in (0, 1):
        root[key] = bool(v)
        return bool(v)
    if isinstance(v, str):
        s = v.strip().lower()
        if s in {"1", "true", "yes", "y", "on"}:
            root[key] = True
            return True
        if s in {"0", "false", "no", "n", "off"}:
            root[key] = False
            return False
    # fallback
    root[key] = bool(default)
    return bool(default)


def _ensure_float(root: Json, key: str, default: float = 0.0) -> float:
    if key not in root:
        root[key] = float(default)
        return float(default)
    try:
        root[key] = float(root.get(key))
        return float(root[key])
    except Exception:
        root[key] = float(default)
        return float(default)


def _migrate_v0_to_v1(st: Json) -> Json:
    """
    v0 -> v1: introduce explicit state_version and normalize minimal roots.

    v0 characteristics:
      - no 'state_version'
      - may have missing roots or wrong shapes
    """
    # Chain meta
    _ensure_int(st, "height", 0)
    _ensure_str(st, "tip", "")

    # Required roots
    accounts = _ensure_dict(st, "accounts")
    _ensure_dict(st, "roles")
    _ensure_dict(st, "blocks")
    _ensure_dict(st, "params")
    _ensure_dict(st, "block_attestations")

    # Finality root
    finalized = st.get("finalized")
    if not isinstance(finalized, dict):
        finalized = {"height": 0, "block_id": ""}
        st["finalized"] = finalized
    _ensure_int(finalized, "height", 0)
    _ensure_str(finalized, "block_id", "")

    # Minimal account normalization (only if existing)
    if isinstance(accounts, dict):
        for aid, acct in list(accounts.items()):
            if not isinstance(acct, dict):
                accounts[aid] = {}
                acct = accounts[aid]
            _ensure_int(acct, "nonce", 0)
            _ensure_int(acct, "poh_tier", 0)
            _ensure_bool(acct, "banned", False)
            _ensure_bool(acct, "locked", False)
            _ensure_float(acct, "reputation", 0.0)

    st["state_version"] = 1
    return st


_MIGRATIONS: Dict[int, Callable[[Json], Json]] = {
    0: _migrate_v0_to_v1,
}


def migrate_state_dict(raw: Any) -> Json:
    """
    Upgrade a raw persisted JSON dict to CURRENT_STATE_VERSION.

    - Best-effort: never raises for simple shape issues; it normalizes.
    - If raw isn't a dict, returns an empty vCURRENT state skeleton.
    """
    st: Json = raw if isinstance(raw, dict) else {}

    v = _as_int(st.get("state_version"), 0)
    if v > CURRENT_STATE_VERSION:
        # Future state created by a newer binary; refuse to downgrade silently.
        raise ValueError(
            f"Ledger state version {v} is newer than this binary supports (max {CURRENT_STATE_VERSION})."
        )

    while v < CURRENT_STATE_VERSION:
        step = _MIGRATIONS.get(v)
        if step is None:
            raise ValueError(f"No migration path from state_version={v} to {CURRENT_STATE_VERSION}.")
        st = step(st)
        v = _as_int(st.get("state_version"), v + 1)

    # Ensure correct final version tag
    st["state_version"] = CURRENT_STATE_VERSION
    return st
