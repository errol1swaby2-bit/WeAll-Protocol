from __future__ import annotations

import hashlib
import json
from typing import Any, Dict

Json = Dict[str, Any]

# Node-local keys that must never affect consensus state commitments.
_EPHEMERAL_KEYS = {"created_ms", "bft"}


def _strip_ephemeral(obj: Any) -> Any:
    if isinstance(obj, dict):
        out: Dict[str, Any] = {}
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
