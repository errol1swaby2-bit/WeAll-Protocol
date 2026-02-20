# src/weall/runtime/domain_dispatch.py

from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import Any, Dict, Optional, Callable

from weall.runtime.errors import ApplyError
from weall.runtime.state_invariants import ensure_state
from weall.runtime.tx_admission_types import TxEnvelope
from weall.tx.canon import TxIndex

# Domain appliers (each returns Optional[Json]; returning None means "not claimed")
from weall.runtime.apply.consensus import apply_consensus
from weall.runtime.apply.content import apply_content
from weall.runtime.apply.dispute import apply_dispute
from weall.runtime.apply.economics import apply_economics
from weall.runtime.apply.governance import apply_governance
from weall.runtime.apply.groups import apply_groups
from weall.runtime.apply.identity import apply_identity
from weall.runtime.apply.indexing import apply_indexing
from weall.runtime.apply.messaging import apply_messaging
from weall.runtime.apply.networking import apply_networking
from weall.runtime.apply.notifications import apply_notifications
from weall.runtime.apply.poh import apply_poh
from weall.runtime.apply.protocol import apply_protocol
from weall.runtime.apply.reputation import apply_reputation
from weall.runtime.apply.rewards import apply_rewards
from weall.runtime.apply.roles import apply_roles
from weall.runtime.apply.social import apply_social
from weall.runtime.apply.storage import apply_storage
from weall.runtime.apply.treasury import apply_treasury

Json = Dict[str, Any]
ApplyFn = Callable[[Json, Any], Optional[Json]]


def _get(env: Any, key: str, default: Any = None) -> Any:
    """Read a field from either a TxEnvelope-like object or a dict.

    Many tests/tools pass raw dict envelopes directly into apply_tx(), while
    production code typically passes a TxEnvelope object.
    """

    if isinstance(env, dict):
        return env.get(key, default)
    return getattr(env, key, default)


def _tx_type(env: Any) -> str:
    return str(_get(env, "tx_type", "") or "").strip().upper()


@lru_cache(maxsize=1)
def _load_index() -> TxIndex:
    """Load TxIndex once for apply-time canon enforcement.

    We prefer the generated artifact; TxIndex has a fallback to YAML in dev/test.
    """
    # Typical layout: repo/generated/tx_index.json
    here = Path(__file__).resolve()
    for root in [here.parent, *here.parents]:
        cand = root / "generated" / "tx_index.json"
        if cand.exists():
            return TxIndex.load_from_file(cand)
    # Fall back: TxIndex.load_from_file will attempt YAML fallback.
    return TxIndex.load_from_file(Path("generated/tx_index.json"))


def _get_txdef(t: str) -> Optional[Dict[str, Any]]:
    try:
        idx = _load_index()
    except Exception:
        return None
    try:
        return idx.get(t)  # type: ignore[return-value]
    except Exception:
        return None


def _enforce_apply_time_canon(state: Json, env: Any) -> None:
    """Defense-in-depth canon enforcement at apply-time.

    Admission already enforces these constraints, but production must assume blocks
    can be adversarial and apply_tx() may be invoked directly in tests/tools.

    We enforce:
      - receipt_only => parent required
      - system_only or origin=SYSTEM => system flag required AND signer is system_signer/SYSTEM
    """
    t = _tx_type(env)
    txdef = _get_txdef(t)
    if not isinstance(txdef, dict):
        return

    # Receipt-only txs may require a parent pointer (block context) depending on canon.
    # Canon distinguishes "receipt_only" (not mempool-admissible) from whether a
    # parent reference is *required*.
    if bool(txdef.get("receipt_only", False)):
        parent_required = str(txdef.get("parent") or "").strip()
        if parent_required:
            parent = _get(env, "parent", None)
            if parent is None or not str(parent).strip():
                raise ApplyError("forbidden", "receipt_only_requires_parent", {"tx_type": t, "parent_required": parent_required})

    # Canon-derived system-only/origin=SYSTEM enforcement at apply-time.
    origin = str(txdef.get("origin") or "").strip().upper()
    if bool(txdef.get("system_only", False)) or origin == "SYSTEM":
        system_flag = bool(_get(env, "system", False))
        if not system_flag:
            raise ApplyError("forbidden", "system_flag_required", {"tx_type": t})

        signer = str(_get(env, "signer", "") or "").strip()
        system_signer = str(state.get("params", {}).get("system_signer") or "").strip()
        if signer not in {system_signer, "SYSTEM"}:
            raise ApplyError(
                "forbidden",
                "system_signer_required",
                {"tx_type": t, "signer": signer, "system_signer": system_signer},
            )


_APPLIERS: tuple[ApplyFn, ...] = (
    apply_identity,
    apply_poh,
    apply_roles,
    apply_reputation,
    apply_content,
    apply_social,
    apply_groups,
    apply_messaging,
    apply_notifications,
    apply_storage,
    apply_networking,
    apply_indexing,
    apply_economics,
    apply_rewards,
    apply_treasury,
    apply_governance,
    apply_dispute,
    apply_protocol,
    apply_consensus,
)


def apply_tx(state: Json, env: Any) -> Json:
    """Dispatch a TxEnvelope to the first domain applier that claims it."""

    ensure_state(state)

    # Tests and some tools pass raw dict envelopes. Normalize to TxEnvelope so
    # domain appliers can rely on attribute access.
    env_norm: Any = env
    if isinstance(env, dict):
        env_norm = TxEnvelope.from_json(env)

    t = _tx_type(env_norm)
    if not t:
        raise ApplyError("invalid_tx", "missing_tx_type", {"tx_type": t})

    _enforce_apply_time_canon(state, env_norm)

    for fn in _APPLIERS:
        try:
            out = fn(state, env_norm)
        except ApplyError:
            raise
        except Exception as e:
            code = getattr(e, "code", None)
            reason = getattr(e, "reason", None)
            details = getattr(e, "details", None)

            if code is not None or reason is not None:
                raise ApplyError(
                    str(code or "domain_error"),
                    str(reason or type(e).__name__),
                    details if details is not None else {"tx_type": t, "domain": fn.__name__},
                ) from e

            raise ApplyError(
                "domain_error",
                type(e).__name__,
                {"tx_type": t, "domain": fn.__name__, "error": str(e)},
            ) from e

        if out is not None:
            return out

    raise ApplyError("tx_unimplemented", "tx_type_not_implemented", {"tx_type": t})
