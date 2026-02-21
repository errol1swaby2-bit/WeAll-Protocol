# src/weall/runtime/domain_apply.py
# ---------------------------------------------------------------------------
# Public, stable import path for applying tx envelopes.
# ---------------------------------------------------------------------------

from __future__ import annotations

import copy
from typing import Any, Dict, Optional

from weall.runtime.domain_apply_all import ApplyError, apply_tx
from weall.runtime.tx_admission_types import TxEnvelope

Json = Dict[str, Any]


def _is_system(env: Any) -> bool:
    if isinstance(env, dict):
        return bool(env.get("system", False))
    return bool(getattr(env, "system", False))


def _signer(env: Any) -> str:
    if isinstance(env, dict):
        return str(env.get("signer") or "").strip()
    return str(getattr(env, "signer", "") or "").strip()


def _nonce(env: Any) -> int:
    if isinstance(env, dict):
        try:
            return int(env.get("nonce") or 0)
        except Exception:
            return 0
    try:
        return int(getattr(env, "nonce", 0) or 0)
    except Exception:
        return 0


def _consume_nonce_if_possible(state: Json, env: Any) -> None:
    """Consume nonce as a deliberate side effect.

    Production rule:
      - non-system txs consume nonce even if apply fails (prevents account deadlock)
      - system txs do not consume nonce

    This function only mutates the account nonce and nothing else.
    """

    if _is_system(env):
        return

    signer = _signer(env)
    if not signer:
        return

    acct = state.get("accounts", {}).get(signer)
    if not isinstance(acct, dict):
        return

    acct["nonce"] = int(_nonce(env))


def apply_tx_atomic(
    state: Json,
    env: Any,
    *,
    consume_nonce_on_fail: bool = True,
) -> Optional[Json]:
    """Apply a tx with fail-atomic semantics.

    On success:
      - state is updated as if apply_tx() ran directly.

    On ApplyError:
      - state remains unchanged, except (optionally) nonce consumption.

    This is consensus-safety critical: we must never allow partial state
    mutation when a tx is rejected during apply.
    """

    # Normalize dict envelopes for domain appliers.
    env_norm: Any = env
    if isinstance(env, dict):
        env_norm = TxEnvelope.from_json(env)

    # Apply on a deep copy to guarantee atomicity.
    snapshot = copy.deepcopy(state)

    try:
        meta = apply_tx(snapshot, env_norm)
    except ApplyError:
        if consume_nonce_on_fail:
            try:
                _consume_nonce_if_possible(state, env_norm)
            except Exception:
                pass
        raise

    # Commit by replacing contents in-place so callers holding references
    # to `state` see the updated view.
    state.clear()
    state.update(snapshot)
    return meta


__all__ = ["ApplyError", "apply_tx", "apply_tx_atomic", "Json"]
