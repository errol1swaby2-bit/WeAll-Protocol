from __future__ import annotations

import os
import re
import time
from pathlib import Path


class FailpointTriggered(RuntimeError):
    """Raised when a test-only failpoint is triggered."""


def _sanitize(name: str) -> str:
    return re.sub(r"[^A-Za-z0-9]+", "_", str(name or "")).strip("_").upper() or "FAILPOINT"


def _active_failpoints() -> set[str]:
    raw = str(os.environ.get("WEALL_TEST_FAILPOINTS") or os.environ.get("WEALL_TEST_FAILPOINT") or "")
    return {part.strip() for part in raw.split(",") if part.strip()}


def maybe_trigger_failpoint(name: str) -> None:
    """Trigger a test-only failpoint if configured in the environment."""
    name_s = str(name or "").strip()
    if not name_s:
        return
    if name_s not in _active_failpoints():
        return

    marker_dir = str(os.environ.get("WEALL_TEST_FAILPOINT_MARKER_DIR") or "").strip()
    if marker_dir:
        try:
            p = Path(marker_dir) / f"{name_s}.marker"
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text("triggered\n", encoding="utf-8")
        except Exception:
            pass

    key = _sanitize(name_s)
    sleep_raw = os.environ.get(f"WEALL_TEST_FAILPOINT_SLEEP_MS_{key}")
    if sleep_raw is None:
        sleep_raw = os.environ.get("WEALL_TEST_FAILPOINT_SLEEP_MS")
    try:
        sleep_ms = int(str(sleep_raw or "0"))
    except Exception:
        sleep_ms = 0
    if sleep_ms > 0:
        time.sleep(float(sleep_ms) / 1000.0)

    action = str(os.environ.get("WEALL_TEST_FAILPOINT_ACTION") or "raise").strip().lower()
    if action == "exit":
        try:
            code = int(str(os.environ.get("WEALL_TEST_FAILPOINT_EXIT_CODE") or "91"))
        except Exception:
            code = 91
        os._exit(code)
    raise FailpointTriggered(f"failpoint:{name_s}")
