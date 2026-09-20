from __future__ import annotations

import copy
from collections.abc import Callable
from typing import Any, Dict

from weall.runtime.reputation_units import sync_account_reputation

Json = dict[str, Any]

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
    root[key] = bool(default)
    return bool(default)


def _migrate_v0_to_v1(st: Json) -> Json:
    _ensure_int(st, "height", 0)
    _ensure_str(st, "tip", "")

    accounts = _ensure_dict(st, "accounts")
    _ensure_dict(st, "roles")
    _ensure_dict(st, "blocks")
    _ensure_dict(st, "params")
    _ensure_dict(st, "block_attestations")

    finalized = st.get("finalized")
    if not isinstance(finalized, dict):
        finalized = {"height": 0, "block_id": ""}
        st["finalized"] = finalized
    _ensure_int(finalized, "height", 0)
    _ensure_str(finalized, "block_id", "")

    if isinstance(accounts, dict):
        for aid, acct in list(accounts.items()):
            if not isinstance(acct, dict):
                accounts[aid] = {}
                acct = accounts[aid]
            _ensure_int(acct, "nonce", 0)
            _ensure_int(acct, "poh_tier", 0)
            _ensure_bool(acct, "banned", False)
            _ensure_bool(acct, "locked", False)
            acct.setdefault("reputation", "0")
            sync_account_reputation(acct, default_units=0)

    st["state_version"] = 1
    return st


_MIGRATIONS: Dict[int, Callable[[Json], Json]] = {
    0: _migrate_v0_to_v1,
}


def _parse_state_version(st: Json) -> int:
    if "state_version" not in st:
        return 0
    raw = st.get("state_version")
    if isinstance(raw, bool):
        raise ValueError("Ledger state_version must be a non-negative integer, not bool.")
    if isinstance(raw, int):
        version = raw
    elif isinstance(raw, str) and raw.strip().isdigit():
        version = int(raw.strip())
    else:
        raise ValueError("Ledger state_version must be a non-negative integer.")
    if version < 0:
        raise ValueError("Ledger state_version must be non-negative.")
    return version


def migrate_state_dict(raw: Any) -> Json:
    """Return a deterministic migrated copy of ``raw``.

    Migration is copy-on-write: neither a successful migration nor a failed
    migration may mutate the caller's object. Each registered step must advance
    the version by exactly one so a malformed step cannot skip compatibility
    boundaries or loop indefinitely.
    """

    source: Json = raw if isinstance(raw, dict) else {}
    st: Json = copy.deepcopy(source)

    v = _parse_state_version(st)
    if v > CURRENT_STATE_VERSION:
        raise ValueError(
            f"Ledger state version {v} is newer than this binary supports (max {CURRENT_STATE_VERSION})."
        )

    while v < CURRENT_STATE_VERSION:
        step = _MIGRATIONS.get(v)
        if step is None:
            raise ValueError(
                f"No migration path from state_version={v} to {CURRENT_STATE_VERSION}."
            )
        migrated = step(st)
        if not isinstance(migrated, dict):
            raise ValueError(f"Migration step {v}->{v + 1} did not return a state object.")
        next_version = _parse_state_version(migrated)
        if next_version != v + 1:
            raise ValueError(
                f"Migration step {v}->{v + 1} produced state_version={next_version}; exact advancement required."
            )
        st = migrated
        v = next_version

    st["state_version"] = CURRENT_STATE_VERSION
    return st
