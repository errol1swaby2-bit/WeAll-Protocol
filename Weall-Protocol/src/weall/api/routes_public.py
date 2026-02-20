# projects/Weall-Protocol/src/weall/api/routes_public.py
from __future__ import annotations

from fastapi import APIRouter

from weall.api.routes_public_parts.accounts import router as accounts_router
from weall.api.routes_public_parts.content import router as content_router
from weall.api.routes_public_parts.health import router as health_router
from weall.api.routes_public_parts.poh import router as poh_router
from weall.api.routes_public_parts.state import router as state_router
from weall.api.routes_public_parts.status import router as status_router
from weall.api.routes_public_parts.gov import router as gov_router
from weall.api.routes_public_parts.groups import router as groups_router
from weall.api.routes_public_parts.media import router as media_router
from weall.api.routes_public_parts.mempool import router as mempool_router
from weall.api.routes_public_parts.tx import router as tx_router
from weall.api.routes_public_parts.consensus import router as consensus_router
from weall.api.routes_public_parts.storage_ops import router as storage_ops_router
from weall.api.routes_public_parts.net_debug import router as net_debug_router
from weall.api.routes_public_parts.net_self import router as net_self_router
from weall.api.routes_public_parts.metrics import router as metrics_router

public_router = APIRouter()

# Versioned API surface (production)
public_router.include_router(health_router, prefix="/v1", tags=["health"])
public_router.include_router(status_router, prefix="/v1", tags=["status"])
public_router.include_router(state_router, prefix="/v1", tags=["state"])
public_router.include_router(accounts_router, prefix="", tags=["accounts"])
public_router.include_router(mempool_router, prefix="/v1", tags=["mempool"])
public_router.include_router(tx_router, prefix="/v1", tags=["tx"])
public_router.include_router(consensus_router, prefix="/v1", tags=["consensus"])
public_router.include_router(poh_router, prefix="/v1", tags=["poh"])
public_router.include_router(content_router, prefix="/v1", tags=["content"])
public_router.include_router(gov_router, prefix="/v1", tags=["governance"])
public_router.include_router(groups_router, prefix="/v1", tags=["groups"])
public_router.include_router(media_router, prefix="/v1", tags=["media"])
public_router.include_router(storage_ops_router, prefix="/v1", tags=["storage"])

# Ops
public_router.include_router(metrics_router, prefix="/v1", tags=["metrics"])

# Mesh debug (read-only)
public_router.include_router(net_debug_router, prefix="/v1", tags=["net"])
public_router.include_router(net_self_router, prefix="/v1", tags=["net"])
