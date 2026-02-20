from __future__ import annotations

from fastapi import APIRouter, Response

from weall.runtime.metrics import format_prometheus, metrics_enabled


router = APIRouter()


@router.get("/metrics")
def metrics() -> Response:
    """Prometheus-style metrics.

    Disabled by default. Enable with:
      WEALL_METRICS_ENABLED=1
    """
    if not metrics_enabled():
        return Response(status_code=404, content="not_found\n", media_type="text/plain")
    return Response(content=format_prometheus(), media_type="text/plain")
