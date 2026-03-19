# src/weall/api/structured_logging.py
from __future__ import annotations

import json
import logging
import os
import time
import uuid
from typing import Any

from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import Response

Json = dict[str, Any]
_VALID_BOOL_TRUE = {"1", "true", "yes", "y", "on"}
_VALID_BOOL_FALSE = {"0", "false", "no", "n", "off"}
_VALID_LOG_LEVELS = {"CRITICAL", "ERROR", "WARNING", "INFO", "DEBUG", "NOTSET"}


def _now_ms() -> int:
    return int(time.time() * 1000)


def _mode() -> str:
    if os.environ.get("PYTEST_CURRENT_TEST") and not os.environ.get("WEALL_MODE"):
        return "test"
    return str(os.environ.get("WEALL_MODE", "prod") or "prod").strip().lower() or "prod"


def _truthy(v: str | None) -> bool:
    if v is None:
        return False
    return v.strip().lower() in _VALID_BOOL_TRUE


def _env_bool(name: str, default: bool) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return bool(default)
    s = str(raw).strip().lower()
    if s == "":
        return bool(default)
    if s in _VALID_BOOL_TRUE:
        return True
    if s in _VALID_BOOL_FALSE:
        return False
    if _mode() == "prod":
        raise ValueError(f"invalid_boolean_env:{name}")
    return bool(default)


def _log_level() -> int:
    raw = os.environ.get("WEALL_LOG_LEVEL")
    if raw is None:
        level_name = "INFO"
    else:
        level_name = str(raw).strip().upper() or "INFO"
        if level_name not in _VALID_LOG_LEVELS:
            if _mode() == "prod":
                raise ValueError("invalid_log_level_env:WEALL_LOG_LEVEL")
            level_name = "INFO"
    return getattr(logging, level_name, logging.INFO)


def configure_structured_logging() -> None:
    """Configure stdlib logging for JSONL output (stdout).

    - Dependency-free.
    - Level from WEALL_LOG_LEVEL (default INFO).
    - Safe to call multiple times.
    """
    level = _log_level()

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
    root._weall_configured = True  # type: ignore[attr-defined]


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
        self._enabled = _env_bool("WEALL_LOG_REQUESTS", True)
        self._log_headers = _env_bool("WEALL_LOG_REQUEST_HEADERS", False)
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
        err: str | None = None
        response: Response | None = None

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
