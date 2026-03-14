# src/weall/runtime/domain_apply.py
# ---------------------------------------------------------------------------
# Public, stable import path for applying tx envelopes.
# ---------------------------------------------------------------------------

from __future__ import annotations

import copy
from typing import Any, Dict, Optional

from weall.runtime.account_id import is_valid_account_id, strict_account_ids_enabled
from weall.runtime.domain_apply_all import ApplyError, apply_tx as _apply_tx_internal
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


def _require_valid_signer_format(env: Any) -> None:
    """Fail-closed signer format enforcement at apply-time.

    Consensus must not depend on the HTTP boundary being correct; blocks can be
    adversarial.
    """

    if _is_system(env):
        return

    signer = _signer(env)
    if not signer:
        raise ApplyError("invalid_tx", "missing_signer", {})

    if strict_account_ids_enabled() and not is_valid_account_id(signer):
        raise ApplyError("invalid_tx", "bad_signer_format", {"signer": signer})


def apply_tx_atomic(
    state: Json,
    env: Any,
    *,
    consume_nonce_on_fail: bool = True,
) -> Json:
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

    # Fail-closed signer format.
    _require_valid_signer_format(env_norm)

    # Apply on a deep copy to guarantee atomicity.
    snapshot = copy.deepcopy(state)

    try:
        _ = _apply_tx_internal(snapshot, env_norm)
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

    # Always consume nonce on success for non-system txs.
    try:
        _consume_nonce_if_possible(state, env_norm)
    except Exception:
        pass

    # Return the updated state object (stable, test-friendly API).
    return state


def apply_tx_atomic_meta(
    state: Json,
    env: Any,
    *,
    consume_nonce_on_fail: bool = True,
) -> Optional[Json]:
    """Apply a tx atomically and return apply metadata.

    This is an executor-facing helper that preserves access to the apply-layer
    return value (if any) without breaking the long-standing test expectation
    that `apply_tx_atomic(...)` returns the updated state.
    """

    # Normalize dict envelopes for domain appliers.
    env_norm: Any = env
    if isinstance(env, dict):
        env_norm = TxEnvelope.from_json(env)

    # Fail-closed signer format.
    _require_valid_signer_format(env_norm)

    snapshot = copy.deepcopy(state)

    try:
        meta = _apply_tx_internal(snapshot, env_norm)
    except ApplyError:
        if consume_nonce_on_fail:
            try:
                _consume_nonce_if_possible(state, env_norm)
            except Exception:
                pass
        raise

    state.clear()
    state.update(snapshot)

    try:
        _consume_nonce_if_possible(state, env_norm)
    except Exception:
        pass

    return meta


def apply_tx(state: Json, env: Any) -> Optional[Json]:
    """Apply a tx envelope with consensus-aligned nonce semantics.

    Many unit tests in this repo use apply_tx(...) directly and expect
    Policy-B behavior:
      - fail-atomic apply
      - nonce consumption even when apply rejects (non-system)

    The executor calls apply_tx_atomic(...) directly; this wrapper maintains
    the stable import path for tests/tools.
    """

    # Keep returning metadata for this wrapper (used by some tools), while
    # `apply_tx_atomic(...)` returns the updated state for tests.
    return apply_tx_atomic_meta(state, env, consume_nonce_on_fail=True)


__all__ = ["ApplyError", "apply_tx", "apply_tx_atomic", "apply_tx_atomic_meta", "Json"]
