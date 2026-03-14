from __future__ import annotations

import json
import logging
import time
from typing import Any, Dict


Json = Dict[str, Any]


def _now_ms() -> int:
    return int(time.time() * 1000)


def log_event(logger: logging.Logger, event: str, **fields: Any) -> None:
    """Emit a single JSONL log event.

    Dependency-free and safe for low-level subsystems (net/ledger/etc.).
    """
    payload: Json = {"ts_ms": _now_ms(), "event": str(event)}
    payload.update(fields)
    try:
        logger.info(json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False))
    except Exception:
        parts = [f"event={event}"] + [f"{k}={fields.get(k)!r}" for k in sorted(fields.keys())]
        logger.info(" ".join(parts))
