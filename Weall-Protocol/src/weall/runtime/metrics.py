from __future__ import annotations

import os
import threading
import time
from typing import Dict


_lock = threading.Lock()
_counters: Dict[str, int] = {}
_gauges: Dict[str, int] = {}
_started_ms = int(time.time() * 1000)


def metrics_enabled() -> bool:
    v = (os.environ.get("WEALL_METRICS_ENABLED") or "").strip().lower()
    if not v:
        return False
    return v in {"1", "true", "yes", "y", "on"}


def inc_counter(name: str, value: int = 1) -> None:
    n = str(name or "").strip()
    if not n:
        return
    try:
        v = int(value)
    except Exception:
        v = 1
    with _lock:
        _counters[n] = int(_counters.get(n, 0)) + int(v)


def set_gauge(name: str, value: int) -> None:
    n = str(name or "").strip()
    if not n:
        return
    try:
        v = int(value)
    except Exception:
        v = 0
    with _lock:
        _gauges[n] = int(v)


def snapshot() -> dict:
    with _lock:
        return {
            "ts_ms": int(time.time() * 1000),
            "started_ms": int(_started_ms),
            "uptime_ms": int(time.time() * 1000) - int(_started_ms),
            "counters": dict(_counters),
            "gauges": dict(_gauges),
        }


def format_prometheus(prefix: str = "weall_") -> str:
    """Best-effort Prometheus exposition text.

    We keep it extremely simple: integer counters/gauges only.
    """
    pre = str(prefix or "").strip() or "weall_"
    snap = snapshot()
    lines: list[str] = []

    # stable base metrics
    lines.append(f"{pre}uptime_ms {int(snap.get('uptime_ms') or 0)}")

    c = snap.get("counters") if isinstance(snap.get("counters"), dict) else {}
    g = snap.get("gauges") if isinstance(snap.get("gauges"), dict) else {}

    for k in sorted(c.keys()):
        name = str(k).strip()
        if not name:
            continue
        try:
            lines.append(f"{pre}{name} {int(c[name])}")
        except Exception:
            continue

    for k in sorted(g.keys()):
        name = str(k).strip()
        if not name:
            continue
        try:
            lines.append(f"{pre}{name} {int(g[name])}")
        except Exception:
            continue

    return "\n".join(lines) + "\n"
