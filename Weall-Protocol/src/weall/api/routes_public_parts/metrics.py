from __future__ import annotations

import os

from fastapi import APIRouter, HTTPException, Request, Response

from weall.runtime.metrics import format_prometheus, metrics_enabled

router = APIRouter()


def _truthy(v: str | None) -> bool:
    return (v or "").strip().lower() in {"1", "true", "yes", "y", "on"}


def _require_metrics_token(request: Request) -> None:
    """If WEALL_METRICS_TOKEN is set, require it.

    Accepted:
      - Authorization: Bearer <token>
      - X-WeAll-Metrics-Token: <token>
    """
    token = (os.environ.get("WEALL_METRICS_TOKEN") or "").strip()
    if not token:
        return

    hdr = (request.headers.get("x-weall-metrics-token") or "").strip()
    auth = (request.headers.get("authorization") or "").strip()

    if hdr == token:
        return

    if auth.lower().startswith("bearer "):
        if auth.split(" ", 1)[1].strip() == token:
            return

    raise HTTPException(status_code=404, detail="Not Found")


@router.get("/metrics")
def metrics(request: Request) -> Response:
    """Prometheus-style metrics.

    Disabled by default. Enable with:
      WEALL_METRICS_ENABLED=1

    Production posture:
      - If WEALL_METRICS_TOKEN is set, metrics require the token.
      - Otherwise they are open (operator choice).
    """
    if not metrics_enabled():
        return Response(status_code=404, content="not_found\n", media_type="text/plain")

    # Fail-closed in prod if a token is configured.
    _require_metrics_token(request)

    return Response(content=format_prometheus(), media_type="text/plain")
