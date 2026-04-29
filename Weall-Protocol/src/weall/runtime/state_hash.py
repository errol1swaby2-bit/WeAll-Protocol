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


def compute_state_root(state: Json) -> str:
    stripped = _strip_ephemeral(state)
    canonical = _canonical(stripped)
    payload = json.dumps(canonical, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()
