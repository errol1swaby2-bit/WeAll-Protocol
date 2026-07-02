from __future__ import annotations

import hashlib
import json
from typing import Any, Final

Json = dict[str, Any]

# Consensus-critical contract.
#
# These keys may appear in local snapshots and API/status payloads, but they must
# never affect the committed state root because they are operational or circular
# tip-tracking metadata rather than durable ledger semantics.
#
# Keep this set synchronized with the authoritative protocol specification.
_EPHEMERAL_KEYS: Final[frozenset[str]] = frozenset(
    {
        "created_ms",
        "bft",
        "meta",
        "tip_hash",
        "tip_ts_ms",
    }
)


def _strip_ephemeral(obj: Any) -> Any:
    if isinstance(obj, dict):
        out: dict[str, Any] = {}
        for k, v in obj.items():
            ks = str(k)
            if ks in _EPHEMERAL_KEYS:
                continue
            out[ks] = _strip_ephemeral(v)
        return out
    if isinstance(obj, list):
        return [_strip_ephemeral(x) for x in obj]
    return obj


def _canonical(obj: Any) -> Any:
    if isinstance(obj, dict):
        return {str(k): _canonical(obj[k]) for k in sorted(obj.keys(), key=lambda x: str(x))}
    if isinstance(obj, list):
        return [_canonical(x) for x in obj]
    return obj


def _canonical_without_ephemeral(obj: Any) -> Any:
    """Return the canonical state-root view in one deterministic tree walk.

    The previous implementation first constructed a full copy with ephemeral
    keys removed and then walked that copy again to sort/stringify keys.  Under
    sustained-load rehearsal the state-root phase is dominated by this
    whole-state traversal.  This helper preserves the exact committed JSON view
    while combining the two passes into one local, non-cached transformation.

    Consensus contract:
      - ephemeral keys are still excluded at every depth;
      - dictionary keys are still ordered by ``str(key)``;
      - committed keys are still stringified before JSON encoding;
      - list order is unchanged;
      - no cross-block or process-local cache is introduced.
    """

    if isinstance(obj, dict):
        out: dict[str, Any] = {}
        for k in sorted(obj.keys(), key=lambda x: str(x)):
            ks = str(k)
            if ks in _EPHEMERAL_KEYS:
                continue
            out[ks] = _canonical_without_ephemeral(obj[k])
        return out
    if isinstance(obj, list):
        return [_canonical_without_ephemeral(x) for x in obj]
    return obj


def compute_state_root(state: Json) -> str:
    canonical = _canonical_without_ephemeral(state)
    payload = json.dumps(canonical, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()
