# src/weall/runtime/domain_dispatch.py

from __future__ import annotations

import logging
from collections.abc import Callable
from functools import lru_cache
from pathlib import Path
from typing import Any

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
from weall.runtime.errors import ApplyError
from weall.runtime.metrics import inc_counter
from weall.runtime.state_invariants import ensure_state
from weall.runtime.tx_admission_types import TxEnvelope
from weall.runtime.tx_contracts import handler_name_for_tx_type, resolve_applier_for_tx_type
from weall.tx.canon import TxIndex

Json = dict[str, Any]
ApplyFn = Callable[[Json, Any], Json | None]

_LOG = logging.getLogger("weall.runtime.domain_dispatch")


def _consensus_bootstrap_open_enabled(state: Json) -> bool:
    params = state.get("params")
    params = params if isinstance(params, dict) else {}
    raw = params.get("poh_bootstrap_open")
    if isinstance(raw, bool):
        return raw
    return str(raw or "").strip().lower() in {"1", "true", "yes", "y", "on"}


def _bootstrap_allowlist_enabled(state: Json) -> bool:
    params = state.get("params")
    params = params if isinstance(params, dict) else {}
    allowlist = params.get("bootstrap_allowlist")
    return isinstance(allowlist, dict) and bool(allowlist)


def _canonical_system_signers(state: Json) -> set[str]:
    params = state.get("params", {}) or {}
    configured = str(params.get("system_signer") or "").strip()
    signers: set[str] = set()
    if configured:
        signers.add(configured)
        if configured.upper() == "SYSTEM":
            signers.add("SYSTEM")
    else:
        signers.add("SYSTEM")
    return signers


def _consensus_bootstrap_policy_mode(state: Json) -> tuple[str, bool]:
    params = state.get("params")
    params = params if isinstance(params, dict) else {}
    raw_mode = str(params.get("poh_bootstrap_mode") or "").strip().lower()
    open_enabled = _consensus_bootstrap_open_enabled(state)
    allowlist_enabled = _bootstrap_allowlist_enabled(state)

    if raw_mode:
        if raw_mode not in {"closed", "open", "allowlist"}:
            return "invalid", True
        if raw_mode == "closed" and (open_enabled or allowlist_enabled):
            return raw_mode, True
        if raw_mode == "open" and allowlist_enabled:
            return raw_mode, True
        if raw_mode == "allowlist" and open_enabled:
            return raw_mode, True
        return raw_mode, False

    if open_enabled and allowlist_enabled:
        return "implicit", True
    if open_enabled:
        return "open", False
    if allowlist_enabled:
        return "allowlist", False
    return "closed", False


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


def _get_txdef(t: str) -> dict[str, Any] | None:
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
      - Option-2 bootstrap founder hard-lock after expiry height
    """

    # ------------------------------------------------------------------
    # Option-2: bootstrap founder account hard-lock after expiry height.
    # ------------------------------------------------------------------
    try:
        params = state.get("params")
        if isinstance(params, dict):
            founder = str(params.get("bootstrap_founder_account") or "").strip()
            expires_h = int(params.get("bootstrap_expires_height") or 0)
            if founder and expires_h > 0:
                signer = str(_get(env, "signer", "") or "").strip()
                # state['height'] is tip height; next applied block is height+1.
                now_h = int(state.get("height") or 0) + 1
                if signer == founder and now_h > int(expires_h):
                    raise ApplyError(
                        "gate_denied",
                        "bootstrap_founder_expired",
                        {"signer": signer, "height": int(now_h), "expires_height": int(expires_h)},
                    )
    except ApplyError:
        raise
    except Exception:
        # Fail-safe: if parsing fails, do not block apply.
        # But NEVER be silent: surface via metric + log so operators can
        # detect that a guardrail is not applying.
        try:
            inc_counter("apply_guard_parse_fail_total", 1)
        except Exception:
            pass
        try:
            _LOG.warning(
                "apply-time guard parse failed for bootstrap founder expiry gate", exc_info=True
            )
        except Exception:
            pass

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
                raise ApplyError(
                    "forbidden",
                    "receipt_only_requires_parent",
                    {"tx_type": t, "parent_required": parent_required},
                )

    # Canon-derived system-only/origin=SYSTEM enforcement at apply-time.
    #
    # POH bootstrap open-mode is consensus-critical and therefore must be driven
    # by replayable ledger state, not process-local environment configuration.
    origin = str(txdef.get("origin") or "").strip().upper()
    system_enforced = bool(txdef.get("system_only", False)) or origin == "SYSTEM"
    if system_enforced and t == "POH_BOOTSTRAP_TIER3_GRANT":
        mode, conflict = _consensus_bootstrap_policy_mode(state)
        if not conflict and mode == "open":
            system_enforced = False

    if system_enforced:
        system_flag = bool(_get(env, "system", False))
        if not system_flag:
            raise ApplyError("forbidden", "system_flag_required", {"tx_type": t})

        signer = str(_get(env, "signer", "") or "").strip()
        canonical_system_signers = _canonical_system_signers(state)
        if signer not in canonical_system_signers:
            raise ApplyError(
                "forbidden",
                "system_signer_required",
                {
                    "tx_type": t,
                    "signer": signer,
                    "system_signers": sorted(canonical_system_signers),
                },
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

    routed = resolve_applier_for_tx_type(t)
    if routed is None:
        raise ApplyError("invalid_tx", "unknown_tx_type", {"tx_type": t})

    try:
        out = routed(state, env_norm)
    except ApplyError:
        raise
    except Exception as e:
        code = getattr(e, "code", None)
        reason = getattr(e, "reason", None)
        details = getattr(e, "details", None)

        if code is not None or reason is not None:
            raise ApplyError(
                str(code or "domain_error"),
                str(reason or "exception"),
                details if isinstance(details, dict) else {"error": repr(e)},
            )

        raise ApplyError("domain_error", "exception", {"error": repr(e)})

    if out is None:
        raise ApplyError(
            "invalid_tx",
            "unclaimed_tx_type",
            {"tx_type": t, "handler": handler_name_for_tx_type(t) or routed.__name__},
        )
    return out
