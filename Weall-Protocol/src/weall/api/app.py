from __future__ import annotations

import os
from contextlib import asynccontextmanager
from typing import List

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from weall.api.config import load_api_config
from weall.api.routes_nodes import router as nodes_router
from weall.api.routes_public import public_router
from weall.api.security import RateLimitMiddleware, RequestSizeLimitMiddleware
from weall.runtime.block_loop import BlockProducerLoop
from weall.runtime.chain_config import load_chain_config
from weall.runtime.executor_boot import build_executor as _build_executor


def build_executor():
    """Build a WeAllExecutor for API runtime.

    This wrapper exists so tests can monkeypatch `weall.api.app.build_executor`
    without reaching into runtime modules.
    """
    return _build_executor()


def _parse_cors_origins() -> List[str]:
    """Parse CORS origins with production-safe defaults.

    Policy:
      - If WEALL_CORS_ORIGINS is unset/empty -> CORS disabled (fail-closed)
      - Wildcard "*" is rejected in WEALL_MODE=prod
      - In non-prod modes, "*" is allowed for convenience

    NOTE:
      In production we never allow "*" so allow_credentials=True remains safe.
    """
    raw = os.environ.get("WEALL_CORS_ORIGINS", "").strip()
    mode = os.environ.get("WEALL_MODE", "prod").strip().lower()

    if not raw:
        return []

    origins = [o.strip() for o in raw.split(",") if o.strip()]

    if "*" in origins:
        if mode == "prod":
            raise RuntimeError(
                "Unsafe CORS configuration: wildcard '*' not allowed in production. "
                "Set explicit origins in WEALL_CORS_ORIGINS."
            )
        return ["*"]

    return origins


def create_app(*, boot_runtime: bool = True) -> FastAPI:
    """Create the FastAPI application.

    boot_runtime:
      - True (default): boot chain config + attach executor
      - False: keep lightweight for unit tests / import-time validation

    Tests rely on:
      - /v1/nodes/seeds
      - /v1/nodes/known
      - request size limiter returning 413 with error.code == "tx_too_large"
      - boot_runtime=True attaches app.state.executor via build_executor()
    """
    mode = os.environ.get("WEALL_MODE", "prod").strip().lower()

    @asynccontextmanager
    async def _lifespan(app: FastAPI):
        """Start/stop runtime services.

        Production intent:
          - executor is attached at create_app time when boot_runtime=True
          - block producer loop can be auto-started via env

        Test safety:
          - if a test monkeypatches build_executor with a stub that lacks
            mempool/attestation_pool, we skip autostart.
        """
        loop = None
        try:
            ex = getattr(app.state, "executor", None)
            autostart = (os.environ.get("WEALL_BLOCK_LOOP_AUTOSTART") or "").strip().lower() in {
                "1",
                "true",
                "yes",
                "y",
                "on",
            }

            if autostart and ex is not None:
                mp = getattr(ex, "mempool", None)
                ap = getattr(ex, "attestation_pool", None)
                if mp is not None and ap is not None:
                    loop = BlockProducerLoop(executor=ex, mempool=mp, attestation_pool=ap)
                    loop.start()
        except Exception:
            # Never fail app startup because the producer loop can't start.
            # Health/ready endpoints expose status so operators can detect it.
            loop = None

        app.state.block_loop = loop
        yield
        try:
            if loop is not None:
                loop.stop()
        except Exception:
            pass

    # Disable docs in production.
    if mode == "prod":
        app = FastAPI(
            title="WeAll Node API",
            docs_url=None,
            redoc_url=None,
            openapi_url=None,
            lifespan=_lifespan,
        )
    else:
        app = FastAPI(title="WeAll Node API", lifespan=_lifespan)

    # Attach API config to app.state for routes that use it.
    app.state.cfg = load_api_config()

    # Runtime boot (expensive): chain config + executor.
    if boot_runtime:
        load_chain_config()
        app.state.executor = build_executor()
    else:
        app.state.executor = None

    # producer loop is attached by lifespan
    app.state.block_loop = None

    # --- Middleware ---
    # Request size limiter should be early to fail fast.
    app.add_middleware(RequestSizeLimitMiddleware)

    # Best-effort per-node rate limiter (single-node Genesis safe default).
    # In multi-replica deployments, enforce at edge and keep this as a backstop.
    app.add_middleware(RateLimitMiddleware)

    # CORS (explicit allowlist only by default).
    cors_origins = _parse_cors_origins()
    if cors_origins:
        app.add_middleware(
            CORSMiddleware,
            allow_origins=cors_origins,
            allow_credentials=True,
            allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
            allow_headers=["Authorization", "Content-Type"],
        )

    # --- Routers ---
    app.include_router(public_router)
    app.include_router(nodes_router)

    return app


# Backwards-compatible module-level app for uvicorn.
app = create_app(boot_runtime=True)
