# src/weall/runtime/domain_apply.py
# ---------------------------------------------------------------------------
# Public, stable import path for applying tx envelopes.
# ---------------------------------------------------------------------------

from __future__ import annotations

import copy
from typing import Any

from weall.runtime.account_id import is_valid_account_id, strict_account_ids_enabled
from weall.runtime.domain_apply_all import ApplyError
from weall.runtime.domain_apply_all import apply_tx as _apply_tx_internal
from weall.runtime.tx_admission_types import TxEnvelope

Json = dict[str, Any]


class NonceSideEffectError(RuntimeError):
    """Consensus-critical nonce mutation failed after or during atomic apply."""


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


def _get_signer_account(state: Json, env: Any) -> Json | None:
    if _is_system(env):
        return None

    signer = _signer(env)
    if not signer:
        raise NonceSideEffectError("nonce_side_effect_missing_signer")

    accounts = state.get("accounts")
    if accounts is None:
        return None
    if not isinstance(accounts, dict):
        raise NonceSideEffectError("nonce_side_effect_accounts_not_object")

    acct = accounts.get(signer)
    if acct is None:
        return None
    if not isinstance(acct, dict):
        raise NonceSideEffectError(f"nonce_side_effect_account_not_object:{signer}")
    return acct


def _consume_nonce_if_possible(state: Json, env: Any) -> None:
    """Commit the canonical envelope nonce after a successful state transition.

    Production rule:
      - non-system txs consume nonce only on successful apply
      - rejected applies must leave signer nonce unchanged
      - system txs do not consume nonce

    This function only mutates the account nonce and nothing else.
    It MUST fail closed on malformed consensus state; silently skipping a
    nonce write would let different nodes commit different post-apply state.
    """

    acct = _get_signer_account(state, env)
    if acct is None:
        return

    try:
        acct["nonce"] = int(_nonce(env))
    except Exception as exc:
        raise NonceSideEffectError(f"nonce_side_effect_write_failed:{type(exc).__name__}") from exc


def _enforce_nonce_convergence(state: Json, env: Any) -> None:
    """Require the post-apply signer nonce to converge to the envelope nonce.

    Domain handlers are allowed to update the account nonce internally, but the
    final committed value must never exceed the canonical envelope nonce.
    Overshoot would indicate divergent per-domain semantics that the atomic
    wrapper would otherwise mask by force-writing the envelope nonce.
    """

    acct = _get_signer_account(state, env)
    if acct is None:
        return

    target = int(_nonce(env))
    current = acct.get("nonce", 0)
    try:
        current_i = int(current or 0)
    except Exception as exc:
        raise NonceSideEffectError(f"nonce_side_effect_invalid_account_nonce:{type(exc).__name__}") from exc

    if current_i > target:
        raise NonceSideEffectError(
            f"nonce_side_effect_overshoot:{_signer(env)}:{current_i}>{target}"
        )


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
    consume_nonce_on_fail: bool = False,
) -> Json:
    """Apply a tx with fail-atomic semantics.

    On success:
      - state is updated as if apply_tx() ran directly.

    On ApplyError:
      - state remains unchanged, including signer nonce.

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
            _consume_nonce_if_possible(state, env_norm)
        raise

    # Commit by replacing contents in-place so callers holding references
    # to `state` see the updated view.
    _enforce_nonce_convergence(snapshot, env_norm)

    state.clear()
    state.update(snapshot)

    # Always consume nonce on success for non-system txs.
    _consume_nonce_if_possible(state, env_norm)

    # Return the updated state object (stable, test-friendly API).
    return state


def apply_tx_atomic_meta(
    state: Json,
    env: Any,
    *,
    consume_nonce_on_fail: bool = False,
) -> Json | None:
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
            _consume_nonce_if_possible(state, env_norm)
        raise

    _enforce_nonce_convergence(snapshot, env_norm)

    state.clear()
    state.update(snapshot)

    _consume_nonce_if_possible(state, env_norm)

    return meta


def apply_tx(state: Json, env: Any) -> Json | None:
    """Apply a tx envelope with consensus-aligned nonce semantics.

    Many unit tests in this repo use apply_tx(...) directly and expect
    Policy-B behavior:
      - fail-atomic apply
      - signer nonce changes only after successful apply (non-system)

    The executor calls apply_tx_atomic(...) directly; this wrapper maintains
    the stable import path for tests/tools.
    """

    # Keep returning metadata for this wrapper (used by some tools), while
    # `apply_tx_atomic(...)` returns the updated state for tests.
    return apply_tx_atomic_meta(state, env, consume_nonce_on_fail=False)


__all__ = [
    "ApplyError",
    "NonceSideEffectError",
    "apply_tx",
    "apply_tx_atomic",
    "apply_tx_atomic_meta",
    "Json",
]
