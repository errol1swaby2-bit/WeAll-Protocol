from __future__ import annotations

import hashlib
import json
from typing import Any, Final

Json = dict[str, Any]

# Consensus-critical state-root projection.
#
# Only these *top-level* fields are excluded from the application state root.
# They are either circular tip metadata or local consensus/runtime state.  Do
# not apply these names recursively: nested objects may legitimately contain
# fields named ``meta`` or ``created_ms`` that affect future state transitions.
_TOP_LEVEL_EPHEMERAL_KEYS: Final[frozenset[str]] = frozenset(
    {
        "created_ms",
        "bft",
        "tip_hash",
        "tip_ts_ms",
    }
)

# ``state["meta"]`` historically mixed local operator posture with protocol
# parameters.  Hashing the entire mapping would make state roots depend on
# node-local values such as runtime_open or clock warnings; excluding the whole
# mapping leaves execution-affecting policy uncommitted.  Project only the
# protocol-semantic keys here until those fields are migrated to a dedicated
# committed namespace.
_CONSENSUS_META_KEYS: Final[frozenset[str]] = frozenset(
    {
        "chain_id",  # legacy snapshots may still carry the chain id here
        "protocol_version",
        "state_root_commitment_version",
        "production_consensus_profile",
        "production_consensus_profile_hash",
        "schema_version",
        "tx_index_hash",
        "reputation_scale",
        "max_block_future_drift_ms",
        "mempool_selection_policy",
        "helper_execution_profile",
        "helper_execution_profile_hash",
        "genesis_bootstrap_profile",
        "genesis_bootstrap_profile_hash",
        "recent_block_anchor_activation_height",
        "constitutional_clock",
        "supported_upgrade_targets",
        "supported_protocol_versions",
    }
)


def _canonical(obj: Any) -> Any:
    if isinstance(obj, dict):
        return {str(k): _canonical(obj[k]) for k in sorted(obj.keys(), key=lambda x: str(x))}
    if isinstance(obj, list):
        return [_canonical(x) for x in obj]
    return obj


def _canonical_meta(meta: Any) -> Any:
    if not isinstance(meta, dict):
        return {}
    out: dict[str, Any] = {}
    for key in sorted(meta.keys(), key=lambda x: str(x)):
        ks = str(key)
        if ks not in _CONSENSUS_META_KEYS:
            continue
        out[ks] = _canonical(meta[key])
    return out


def _canonical_state_root_view(state: Any) -> Any:
    """Return the deterministic application-state commitment view.

    The projection is intentionally path-aware:
      * only known top-level ephemeral fields are excluded;
      * top-level ``meta`` is reduced to execution-affecting protocol fields;
      * nested ``meta``/``created_ms`` fields are committed normally;
      * dictionary keys are stringified and sorted; list order is preserved.

    This prevents two states with equal roots from carrying different protocol
    transition semantics while keeping node-local runtime posture out of the
    root.
    """

    if not isinstance(state, dict):
        return _canonical(state)

    out: dict[str, Any] = {}
    for key in sorted(state.keys(), key=lambda x: str(x)):
        ks = str(key)
        if ks in _TOP_LEVEL_EPHEMERAL_KEYS:
            continue
        if ks == "meta":
            projected = _canonical_meta(state[key])
            if projected:
                out[ks] = projected
            continue
        out[ks] = _canonical(state[key])
    return out


def consensus_state_root_view(state: Json) -> Json:
    """Return a copy of the exact JSON-compatible state-root preimage view."""

    view = _canonical_state_root_view(state)
    if not isinstance(view, dict):
        raise TypeError("state root requires a JSON object")
    return view


def compute_state_root(state: Json) -> str:
    canonical = consensus_state_root_view(state)
    payload = json.dumps(canonical, separators=(",", ":"), ensure_ascii=False, allow_nan=False)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()
