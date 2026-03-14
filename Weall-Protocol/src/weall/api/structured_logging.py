# src/weall/api/structured_logging.py
from __future__ import annotations

import json
import logging
import os
import time
import uuid
from typing import Any, Dict, Optional

from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import Response

Json = Dict[str, Any]


def _now_ms() -> int:
    return int(time.time() * 1000)


def _truthy(v: str | None) -> bool:
    if v is None:
        return False
    return v.strip().lower() in {"1", "true", "yes", "y", "on"}


def configure_structured_logging() -> None:
    """Configure stdlib logging for JSONL output (stdout).

    - Dependency-free.
    - Level from WEALL_LOG_LEVEL (default INFO).
    - Safe to call multiple times.
    """
    level_name = (os.environ.get("WEALL_LOG_LEVEL") or "INFO").strip().upper()
    level = getattr(logging, level_name, logging.INFO)

    root = logging.getLogger()
    if getattr(root, "_weall_configured", False):  # type: ignore[attr-defined]
        root.setLevel(level)
        return

    handler = logging.StreamHandler()
    handler.setLevel(level)
    handler.setFormatter(logging.Formatter("%(message)s"))

    root.handlers = [handler]
    root.setLevel(level)
    root.propagate = False
    setattr(root, "_weall_configured", True)  # type: ignore[attr-defined]


def log_event(logger: logging.Logger, event: str, **fields: Any) -> None:
    payload: Json = {"ts_ms": _now_ms(), "event": event}
    payload.update(fields)
    try:
        logger.info(json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False))
    except Exception:
        parts = [f"event={event}"] + [f"{k}={fields.get(k)!r}" for k in sorted(fields.keys())]
        logger.info(" ".join(parts))


class RequestLogMiddleware(BaseHTTPMiddleware):
    """Structured request logging middleware.

    Controls:
      - WEALL_LOG_REQUESTS=0 to disable (default on)
      - WEALL_LOG_REQUEST_HEADERS=1 to include a small header subset
    """

    def __init__(self, app) -> None:
        super().__init__(app)
        raw = (os.environ.get("WEALL_LOG_REQUESTS") or "1").strip().lower()
        self._enabled = raw not in {"0", "false", "no", "n", "off"}
        self._log_headers = _truthy(os.environ.get("WEALL_LOG_REQUEST_HEADERS"))
        self._logger = logging.getLogger("weall.http")

    def _mk_request_id(self) -> str:
        return uuid.uuid4().hex

    def _header_subset(self, request: Request) -> Json:
        if not self._log_headers:
            return {}
        out: Json = {}
        for k in ["user-agent", "content-type", "content-length", "x-forwarded-for"]:
            v = request.headers.get(k)
            if v:
                out[k] = v
        return out

    async def dispatch(self, request: Request, call_next):
        if not self._enabled:
            return await call_next(request)

        started = time.monotonic()
        request_id = request.headers.get("x-request-id") or self._mk_request_id()

        try:
            request.state.request_id = request_id  # type: ignore[attr-defined]
        except Exception:
            pass

        status = 500
        err: Optional[str] = None
        response: Optional[Response] = None

        try:
            response = await call_next(request)
            status = int(getattr(response, "status_code", 200) or 200)
            return response
        except Exception as e:
            err = str(e)
            raise
        finally:
            dur_ms = int((time.monotonic() - started) * 1000)
            log_event(
                self._logger,
                "http_request",
                request_id=request_id,
                method=request.method,
                path=str(request.url.path or ""),
                status=status,
                duration_ms=dur_ms,
                client=str(getattr(request.client, "host", "")) if request.client else "",
                headers=self._header_subset(request),
                error=err,
            )
            try:
                if response is not None:
                    response.headers.setdefault("x-request-id", request_id)
            except Exception:
                pass
