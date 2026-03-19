from __future__ import annotations

import os
import sys
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles

from weall.api.config import load_api_config
from weall.api.errors import ApiError
from weall.api.routes_public import public_router
from weall.api.security import RateLimitMiddleware, RequestSizeLimitMiddleware
from weall.net.net_loop import NetMeshLoop
from weall.runtime.block_loop import BlockProducerLoop
from weall.runtime.chain_config import load_chain_config, production_bootstrap_issues
from weall.runtime.executor_boot import build_executor as _build_executor


class ApiRuntimeLifecycleError(RuntimeError):
    """Raised when production runtime lifecycle setup fails in a fail-closed path."""


def build_executor():
    """Build a WeAllExecutor for API runtime.

    This wrapper exists so tests can monkeypatch `weall.api.app.build_executor`
    without reaching into runtime modules.
    """
    return _build_executor()


def _parse_cors_origins() -> list[str]:
    """Parse CORS origins with production-safe defaults.

    Policy:
      - If WEALL_CORS_ORIGINS is unset/empty -> CORS disabled (fail-closed)
      - Wildcard "*" is rejected in WEALL_MODE=prod
      - In non-prod modes, "*" is allowed for convenience
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


def _truthy_env(name: str) -> bool:
    v = (os.environ.get(name) or "").strip().lower()
    if not v:
        return False
    return v in {"1", "true", "yes", "y", "on"}


def _running_under_pytest() -> bool:
    """Best-effort detection for test imports during pytest collection/runtime."""
    if "pytest" in sys.modules:
        return True

    # During some collection/import phases PYTEST_CURRENT_TEST may not be set yet,
    # but when it is available this is also a reliable signal.
    if os.environ.get("PYTEST_CURRENT_TEST"):
        return True

    return False


def _module_app_boot_runtime_default() -> bool:
    """Decide whether the module-level `app` should boot runtime on import.

    Priority:
      1. Explicit env override via WEALL_API_BOOT_RUNTIME
      2. Under pytest -> False (avoid touching real runtime/DB during import)
      3. Otherwise -> True (normal production/dev server behavior)
    """
    raw = (os.environ.get("WEALL_API_BOOT_RUNTIME") or "").strip().lower()
    if raw:
        return raw in {"1", "true", "yes", "y", "on"}

    if _running_under_pytest():
        return False

    return True


def _api_error_payload(exc: ApiError) -> dict:
    out = {"ok": False, "error": {"code": exc.code, "message": exc.message}}
    if exc.details:
        out["error"]["details"] = exc.details
    return out


def _maybe_mount_web(app: FastAPI) -> None:
    """Optionally serve the built web UI from the node."""
    if not _truthy_env("WEALL_SERVE_WEB"):
        return

    dist_raw = (os.environ.get("WEALL_WEB_DIST_DIR") or "projects/web/dist").strip()
    dist_dir = Path(dist_raw)

    if not dist_dir.is_absolute():
        dist_dir = (Path.cwd() / dist_dir).resolve()

    index_path = dist_dir / "index.html"
    if not dist_dir.exists() or not index_path.exists():
        return

    app.mount("/", StaticFiles(directory=str(dist_dir), html=True), name="weall-web")


def _enforce_prod_runtime_topology() -> None:
    mode = os.environ.get("WEALL_MODE", "prod").strip().lower()
    if mode != "prod":
        return

    bft_enabled = _truthy_env("WEALL_BFT_ENABLED")
    block_loop_autostart = _truthy_env("WEALL_BLOCK_LOOP_AUTOSTART")
    net_loop_autostart = _truthy_env("WEALL_NET_LOOP_AUTOSTART")
    workers_raw = (os.environ.get("GUNICORN_WORKERS") or "1").strip()
    try:
        workers = int(workers_raw or "1")
    except Exception:
        workers = 1

    if bft_enabled and block_loop_autostart:
        raise RuntimeError(
            "Unsafe production runtime: WEALL_BFT_ENABLED=1 cannot be combined with WEALL_BLOCK_LOOP_AUTOSTART=1"
        )
    if (bft_enabled or block_loop_autostart or net_loop_autostart) and workers > 1:
        raise RuntimeError(
            "Unsafe production runtime: GUNICORN_WORKERS must be 1 when consensus/network autostart loops are enabled"
        )


def create_app(*, boot_runtime: bool = True) -> FastAPI:
    """Create the FastAPI application."""
    mode = os.environ.get("WEALL_MODE", "prod").strip().lower()

    @asynccontextmanager
    async def _lifespan(app: FastAPI):
        block_loop = None
        net_loop = None

        ex = getattr(app.state, "executor", None)
        autostart = _truthy_env("WEALL_BLOCK_LOOP_AUTOSTART")
        net_autostart = _truthy_env("WEALL_NET_LOOP_AUTOSTART")
        prod_fail_closed = mode == "prod"

        try:
            if autostart:
                if ex is None:
                    if prod_fail_closed:
                        raise ApiRuntimeLifecycleError(
                            "api_block_loop_start_failed:missing_executor"
                        )
                else:
                    mp = getattr(ex, "mempool", None)
                    ap = getattr(ex, "attestation_pool", None)
                    if mp is None or ap is None:
                        if prod_fail_closed:
                            raise ApiRuntimeLifecycleError(
                                "api_block_loop_start_failed:missing_runtime_dependencies"
                            )
                    else:
                        block_loop = BlockProducerLoop(executor=ex, mempool=mp, attestation_pool=ap)
                        if not block_loop.start():
                            if prod_fail_closed:
                                raise ApiRuntimeLifecycleError(
                                    "api_block_loop_start_failed:start_returned_false"
                                )
                            block_loop = None
        except ApiRuntimeLifecycleError:
            raise
        except Exception as exc:
            block_loop = None
            if prod_fail_closed and autostart:
                raise ApiRuntimeLifecycleError("api_block_loop_start_failed") from exc

        try:
            if net_autostart:
                if ex is None:
                    if prod_fail_closed:
                        raise ApiRuntimeLifecycleError("api_net_loop_start_failed:missing_executor")
                else:
                    mp = getattr(ex, "mempool", None)
                    if mp is None:
                        if prod_fail_closed:
                            raise ApiRuntimeLifecycleError(
                                "api_net_loop_start_failed:missing_runtime_dependencies"
                            )
                    else:
                        net_loop = NetMeshLoop(executor=ex, mempool=mp)
                        if not net_loop.start():
                            net_loop = None
                            if prod_fail_closed:
                                raise ApiRuntimeLifecycleError(
                                    "api_net_loop_start_failed:start_returned_false"
                                )
        except ApiRuntimeLifecycleError:
            raise
        except Exception as exc:
            net_loop = None
            if prod_fail_closed and net_autostart:
                raise ApiRuntimeLifecycleError("api_net_loop_start_failed") from exc

        app.state.block_loop = block_loop
        app.state.net_loop = net_loop
        app.state.net_node = net_loop.node if net_loop is not None else None
        app.state.net = app.state.net_node

        yield

        try:
            if block_loop is not None:
                block_loop.stop()
        except Exception:
            pass

        try:
            if net_loop is not None:
                net_loop.stop()
        except Exception:
            pass

        try:
            ex = getattr(app.state, "executor", None)
            if ex is not None and hasattr(ex, "mark_clean_shutdown"):
                ex.mark_clean_shutdown()
        except Exception:
            pass

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

    @app.exception_handler(ApiError)
    async def _handle_api_error(_request: Request, exc: ApiError):
        return JSONResponse(status_code=int(exc.status_code), content=_api_error_payload(exc))

    app.state.cfg = load_api_config()

    if boot_runtime:
        cfg = load_chain_config()
        _enforce_prod_runtime_topology()
        issues = production_bootstrap_issues(cfg)
        if issues:
            raise RuntimeError("Production bootstrap blocked: " + "; ".join(issues))
        app.state.executor = build_executor()
    else:
        app.state.executor = None

    app.state.block_loop = None
    app.state.net_loop = None
    app.state.net_node = None
    app.state.net = None

    app.add_middleware(RequestSizeLimitMiddleware)
    app.add_middleware(RateLimitMiddleware)

    cors_origins = _parse_cors_origins()
    if cors_origins:
        app.add_middleware(
            CORSMiddleware,
            allow_origins=cors_origins,
            allow_credentials=True,
            allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
            allow_headers=[
                "Accept",
                "Authorization",
                "Content-Type",
                "X-WeAll-Account",
                "X-WeAll-Session-Key",
            ],
        )

    app.include_router(public_router)
    _maybe_mount_web(app)

    return app


app = create_app(boot_runtime=_module_app_boot_runtime_default())
