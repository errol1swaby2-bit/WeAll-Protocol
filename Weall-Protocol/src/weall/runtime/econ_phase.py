# src/weall/runtime/econ_phase.py

from __future__ import annotations

"""Genesis economic lock helpers.

WeAll launches with economics disabled (no fees, rewards, treasury spending).
Economics can only be activated after a time-based lock:

  economic_unlock_time = genesis_time + 90 days

During the lock, *any* economic tx (user or system) must be rejected.
After the unlock time, economics are still disabled until a governance action
(ECONOMICS_ACTIVATION) turns them on.

This module provides:
  - is_econ_unlocked: checks the time lock
  - deny_if_econ_time_locked: rejects if time lock not yet expired
  - deny_if_econ_disabled: canonical gate used by apply modules
  - econ_allowed_from_state: (unlocked AND enabled)
  - is_economic_user_tx / is_economic_system_tx: classify tx types

State assumptions:
  state["params"]["economic_unlock_time"]: unix seconds (int)
  state["params"]["economics_enabled"]: bool
  state["time"]: optional unix seconds (int), used when now not passed
"""

from functools import lru_cache
from pathlib import Path
from typing import Any, Dict, Optional

from weall.tx.canon import TxIndex

Json = Dict[str, Any]

DEFAULT_LOCK_SECONDS: int = 90 * 24 * 60 * 60

# Domains considered "economic" for genesis gating.
# Treasury/rewards are treated as economic because they can move value.
_ECON_DOMAINS = {"Economics", "Treasury", "Rewards"}


def _repo_root() -> Path:
    """Return the repository root (directory that contains /generated)."""

    # econ_phase.py -> runtime -> weall -> src -> REPO_ROOT
    return Path(__file__).resolve().parents[3]


@lru_cache(maxsize=1)
def _tx_index() -> TxIndex:
    """Load the generated tx index for lightweight classification."""

    path = _repo_root() / "generated" / "tx_index.json"
    if not path.exists():
        raise RuntimeError(
            "Missing generated/tx_index.json. "
            "This node build is incomplete; run the generation step or ensure generated artifacts "
            "are included in the deployment package."
        )
    return TxIndex.load_from_file(str(path))


def is_econ_unlocked(state: Json, now_s: Optional[int] = None) -> bool:
    """True if current time is on/after the economic unlock time."""

    params = state.get("params") or {}
    unlock_time = params.get("economic_unlock_time")
    if unlock_time is None:
        # If not set, default to lock starting from genesis_time.
        genesis_time = params.get("genesis_time")
        if genesis_time is None:
            return False
        unlock_time = int(genesis_time) + DEFAULT_LOCK_SECONDS

    if now_s is None:
        now_s = state.get("time")
    if now_s is None:
        return False

    try:
        return int(now_s) >= int(unlock_time)
    except (TypeError, ValueError):
        return False


def _economics_enabled(state: Json) -> bool:
    params = state.get("params") or {}
    return bool(params.get("economics_enabled", False))


def econ_allowed_from_state(state: Json, now_s: Optional[int] = None) -> bool:
    """True only when (unlock_time reached) AND (economics_enabled is true)."""

    return is_econ_unlocked(state, now_s) and _economics_enabled(state)


def deny_if_econ_time_locked(state: Json, now_s: Optional[int] = None) -> None:
    """Raise ValueError if the time-based Genesis economic lock has not expired.

    This gate is used when a tx is only permitted after unlock, regardless of whether
    economics have been activated yet (e.g., ECONOMICS_ACTIVATION itself).
    """

    if now_s is None:
        now_s = state.get("time")

    if not is_econ_unlocked(state, now_s):
        raise ValueError("economics are time-locked")


def is_economic_user_tx(tx_type: str) -> bool:
    """Return True if tx_type is a *user-context* economic tx.

    Used primarily to distinguish "economic transfers" from civic actions.
    """

    try:
        entry = _tx_index().get(tx_type)
    except Exception:
        return False

    if not entry:
        return False

    if str(entry.get("domain", "")) not in _ECON_DOMAINS:
        return False

    return str(entry.get("context", "")).strip().lower() == "user"


def is_economic_system_tx(tx_type: str) -> bool:
    """Return True if tx_type is a non-user (system/block/validator/peer) economic tx."""

    try:
        entry = _tx_index().get(tx_type)
    except Exception:
        return False

    if not entry:
        return False

    if str(entry.get("domain", "")) not in _ECON_DOMAINS:
        return False

    ctx = str(entry.get("context", "")).strip().lower()
    if ctx and ctx != "user":
        return True

    return bool(entry.get("receipt_only", False))


def deny_if_econ_disabled(
    state: Json,
    now_s: Optional[int] = None,
    tx_type: Optional[str] = None,
    *,
    for_activation: bool = False,
) -> None:
    """Raise if the economic subsystem is not allowed right now.

    - Before unlock time: deny everything, including ECONOMICS_ACTIVATION.
    - After unlock time: allow ECONOMICS_ACTIVATION (to turn economics on).
    - After unlock+activation: allow other economic tx.

    This function intentionally raises ValueError so it can be wrapped into the
    appropriate domain ApplyError by callers.
    """

    # Normalize now_s.
    if now_s is None:
        now_s = state.get("time")

    t = (tx_type or "").strip().upper()

    # Allow activation only after the unlock time.
    if t == "ECONOMICS_ACTIVATION":
        if not is_econ_unlocked(state, now_s):
            raise ValueError("economics are time-locked (activation not yet allowed)")
        return

    if not econ_allowed_from_state(state, now_s):
        if not is_econ_unlocked(state, now_s):
            raise ValueError("economics are time-locked")
        raise ValueError("economics are disabled")
