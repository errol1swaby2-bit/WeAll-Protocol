# src/weall/runtime/state_invariants.py
from __future__ import annotations

"""State invariants / normalization helpers.

WeAll state is a nested JSON-like dict that is mutated deterministically by apply_* modules.
In production, we want a *single* place that:

  - validates the state is dict-like
  - ensures core top-level containers exist (so domain modules can rely on them)

This module is intentionally conservative: it only creates *core* containers that are
universally expected (accounts + params). Domain-specific containers remain the
responsibility of the corresponding apply_* module to avoid accidental schema drift.

If you later want stronger guarantees, extend this module and update callsites
accordingly (ideally with migration tests).
"""

from collections.abc import MutableMapping
from typing import Any, Dict

Json = Dict[str, Any]


def ensure_state(st: Any) -> Json:
    """Ensure `st` is a dict and contains core keys.

    Returns the (possibly mutated) dict.

    Raises:
        TypeError: if st is not a MutableMapping
    """
    if not isinstance(st, MutableMapping):
        raise TypeError(f"state must be MutableMapping, got {type(st)}")

    # Accounts is the universal anchor for nonces, PoH tier, bans/locks, etc.
    acc = st.get("accounts")
    if acc is None:
        st["accounts"] = {}
    elif not isinstance(acc, dict):
        # Fail closed: do not attempt to coerce arbitrary types.
        raise TypeError(f"state['accounts'] must be dict, got {type(acc)}")

    # Params carries chain params (genesis_time, system_signer, etc.)
    params = st.get("params")
    if params is None:
        st["params"] = {}
    elif not isinstance(params, dict):
        raise TypeError(f"state['params'] must be dict, got {type(params)}")

    return st  # type: ignore[return-value]


__all__ = ["ensure_state"]
