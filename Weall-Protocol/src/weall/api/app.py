from __future__ import annotations

import os
import sys
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles

from weall.api.config import load_api_config
from weall.api.errors import ApiError
from weall.api.mode_isolation import demo_mode_isolation_issue
from weall.api.routes_public import public_router
from weall.api.routes_public_parts.helper_readiness import (
    router as helper_readiness_router,
)
from weall.api.security import RateLimitMiddleware, RequestSizeLimitMiddleware
from weall.net.net_loop import NetMeshLoop
from weall.runtime.block_loop import BlockProducerLoop
from weall.runtime.chain_config import (
    load_chain_config,
    production_bootstrap_issues,
    validate_runtime_env,
)
from weall.runtime.executor_boot import build_executor as _build_executor
from weall.runtime.node_runtime_config import resolve_node_runtime_config_from_env
from weall.runtime.runtime_authority import strict_runtime_authority_mode


class ApiRuntimeLifecycleError(RuntimeError):
    """Raised when runtime lifecycle setup fails in a fail-closed path."""


def build_executor():
    return _build_executor()


def _executor_node_lifecycle(executor: Any) -> dict[str, Any]:
    status_fn = getattr(executor, "node_lifecycle_status", None)
    if callable(status_fn):
        try:
            out = status_fn()
            if isinstance(out, dict):
                return dict(out)
        except Exception:
            return {}
    return {}


def _startup_authority_contract(executor: Any) -> dict[str, Any]:
    runtime_cfg = resolve_node_runtime_config_from_env()
    lifecycle = _executor_node_lifecycle(executor)
    requested_roles = list(lifecycle.get("service_roles_requested", [])) if isinstance(lifecycle.get("service_roles_requested"), list) else list(runtime_cfg.requested_roles)
    effective_roles = list(lifecycle.get("service_roles_effective", [])) if isinstance(lifecycle.get("service_roles_effective"), list) else []
    helper_requested = bool(lifecycle.get("helper_enabled_requested", runtime_cfg.helper_enabled_requested))
    helper_effective = bool(lifecycle.get("helper_enabled_effective", False))
    bft_requested = bool(lifecycle.get("bft_enabled_requested", runtime_cfg.bft_enabled_requested))
    bft_effective = bool(lifecycle.get("bft_enabled_effective", False))
    validator_requested = bool("validator" in set(requested_roles) or bft_requested)
    validator_effective = bool("validator" in set(effective_roles) and bft_effective)
    return {
        "strict_runtime_authority_mode": bool(strict_runtime_authority_mode()),
        "requested_state": str(lifecycle.get("requested_state", runtime_cfg.requested_state)),
        "effective_state": str(lifecycle.get("effective_state", "")),
        "requested_roles": requested_roles,
        "effective_roles": effective_roles,
        "validator_requested": validator_requested,
        "validator_effective": validator_effective,
        "helper_requested": helper_requested,
        "helper_effective": helper_effective,
        "bft_requested": bft_requested,
        "bft_effective": bft_effective,
        "startup_action": str(lifecycle.get("startup_action", "allow")),
        "promotion_failure_reasons": list(lifecycle.get("promotion_failure_reasons", [])) if isinstance(lifecycle.get("promotion_failure_reasons"), list) else [],
    }


def _persist_startup_authority_contract(app: FastAPI, executor: Any) -> None:
    app.state.startup_authority_contract = _startup_authority_contract(executor)


def _enforce_executor_runtime_authority(executor: Any) -> None:
    contract = _startup_authority_contract(executor)
    if not bool(contract.get("strict_runtime_authority_mode", False)):
        return
    startup_action = str(contract.get("startup_action", "allow") or "allow")
    if startup_action == "refuse_startup":
        raise ApiRuntimeLifecycleError("api_runtime_authority_refused_startup")

    bft_requested = bool(contract.get("bft_requested", False))
    validator_requested = bool(contract.get("validator_requested", False))
    validator_effective = bool(contract.get("validator_effective", False))
    if (bft_requested or validator_requested) and _truthy_env("WEALL_BFT_ENABLED") and not validator_effective:
        raise ApiRuntimeLifecycleError(
            "api_runtime_authority_validator_not_effective"
        )


def _parse_cors_origins() -> list[str]:
    raw = os.environ.get("WEALL_CORS_ORIGINS", "").strip()
    mode = os.environ.get("WEALL_MODE", "prod").strip().lower()

    if not raw:
        if mode == "prod":
            return []
        return [
            "http://localhost:5173",
            "http://127.0.0.1:5173",
            "http://localhost:4173",
            "http://127.0.0.1:4173",
        ]

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


def _enforce_demo_mode_isolation() -> None:
    issue = demo_mode_isolation_issue()
    if issue:
        raise ApiRuntimeLifecycleError(issue)


def _running_under_pytest() -> bool:
    if "pytest" in sys.modules:
        return True
    if os.environ.get("PYTEST_CURRENT_TEST"):
        return True
    return False


def _module_app_boot_runtime_default() -> bool:
    raw = (os.environ.get("WEALL_API_BOOT_RUNTIME") or "").strip().lower()
    if raw:
        return raw in {"1", "true", "yes", "y", "on"}

    if _running_under_pytest():
        return False

    return True


def _api_error_payload(exc: ApiError) -> dict[str, Any]:
    out: dict[str, Any] = {
        "ok": False,
        "error": {"code": exc.code, "message": exc.message},
    }
    if exc.details:
        out["error"]["details"] = exc.details
    return out


def _maybe_mount_web(app: FastAPI) -> None:
    if not _truthy_env("WEALL_SERVE_WEB"):
        return

    dist_raw = (os.environ.get("WEALL_WEB_DIST_DIR") or "projects/web/dist").strip()
    dist_dir = Path(dist_raw)
    if not dist_dir.is_absolute():
        dist_dir = (Path.cwd() / dist_dir).resolve()

    index_path = dist_dir / "index.html"
    if not index_path.exists():
        raise ApiRuntimeLifecycleError(
            f"WEALL_SERVE_WEB=1 but index not found: {index_path}"
        )

    app.mount("/", StaticFiles(directory=str(dist_dir), html=True), name="web")


def _require_single_worker_for_prod_runtime() -> None:
    workers_raw = (os.environ.get("GUNICORN_WORKERS") or "").strip()
    if not workers_raw:
        return
    try:
        workers = int(workers_raw)
    except ValueError as exc:
        raise ApiRuntimeLifecycleError(
            "GUNICORN_WORKERS must be 1 in prod runtime mode."
        ) from exc
    if workers != 1:
        raise ApiRuntimeLifecycleError("GUNICORN_WORKERS must be 1 in prod runtime mode.")


def _enforce_prod_runtime_topology() -> None:
    mode = (os.environ.get("WEALL_MODE") or "").strip().lower()
    if mode != "prod":
        return

    net_enabled = _truthy_env("WEALL_NET_ENABLED")
    bft_enabled = _truthy_env("WEALL_BFT_ENABLED")
    block_loop = _truthy_env("WEALL_BLOCK_LOOP_AUTOSTART")
    net_loop = _truthy_env("WEALL_NET_LOOP_AUTOSTART")

    if bft_enabled and block_loop:
        raise ApiRuntimeLifecycleError(
            "Invalid prod topology: WEALL_BFT_ENABLED=1 cannot be combined with "
            "WEALL_BLOCK_LOOP_AUTOSTART=1."
        )

    if net_loop or block_loop or net_enabled or bft_enabled:
        _require_single_worker_for_prod_runtime()

    if (net_enabled or bft_enabled) and not (
        (os.environ.get("WEALL_NODE_PUBKEY") or "").strip()
        and (os.environ.get("WEALL_NODE_PRIVKEY") or "").strip()
    ):
        raise ApiRuntimeLifecycleError(
            "Invalid prod topology: networking/BFT requires node identity keys."
        )


def _runtime_dependencies_missing_for_block_loop(executor: Any) -> bool:
    return not (
        getattr(executor, "mempool", None) is not None
        and getattr(executor, "attestation_pool", None) is not None
    )


def _construct_block_loop(executor: Any):
    attempts = (
        lambda: BlockProducerLoop(),
        lambda: BlockProducerLoop(
            executor=executor,
            mempool=getattr(executor, "mempool", None),
            attestation_pool=getattr(executor, "attestation_pool", None),
        ),
        lambda: BlockProducerLoop(executor),
    )
    last_exc: Exception | None = None
    for attempt in attempts:
        try:
            return attempt()
        except TypeError as exc:
            last_exc = exc
    if last_exc is not None:
        raise last_exc
    raise ApiRuntimeLifecycleError("api_block_loop_start_failed:constructor_unavailable")


def _start_block_loop(loop: Any, executor: Any) -> bool:
    start = getattr(loop, "start", None)
    if not callable(start):
        raise ApiRuntimeLifecycleError("api_block_loop_start_failed:missing_start_method")

    attempts = (
        lambda: start(),
        lambda: start(executor),
        lambda: start(
            executor=executor,
            mempool=getattr(executor, "mempool", None),
            attestation_pool=getattr(executor, "attestation_pool", None),
        ),
    )
    last_exc: Exception | None = None
    for attempt in attempts:
        try:
            result = attempt()
            return False if result is False else True
        except TypeError as exc:
            last_exc = exc
    if last_exc is not None:
        raise last_exc
    raise ApiRuntimeLifecycleError("api_block_loop_start_failed:invalid_start_signature")


def _stop_block_loop(loop: Any) -> None:
    stop = getattr(loop, "stop", None)
    if callable(stop):
        stop()


def _construct_net_loop(net: Any, executor: Any):
    """
    Tolerate multiple constructor shapes used by production code and tests.

    The failing fake loop in tests requires keyword-only:
      __init__(*, executor, mempool)

    Production code may accept:
      (net=..., executor=...)
      (executor)
      ()
    """
    attempts = (
        lambda: NetMeshLoop(
            executor=executor,
            mempool=getattr(executor, "mempool", None),
        ),
        lambda: NetMeshLoop(
            executor=executor,
            mempool=getattr(executor, "mempool", None),
            net=net,
        ),
        lambda: NetMeshLoop(net=net, executor=executor),
        lambda: NetMeshLoop(net, executor),
        lambda: NetMeshLoop(executor),
        lambda: NetMeshLoop(),
    )
    last_exc: Exception | None = None
    for attempt in attempts:
        try:
            return attempt()
        except TypeError as exc:
            last_exc = exc
    if last_exc is not None:
        raise last_exc
    raise ApiRuntimeLifecycleError("api_net_loop_start_failed:constructor_unavailable")


def _start_net_loop(loop: Any, net: Any, executor: Any) -> bool:
    start = getattr(loop, "start", None)
    if not callable(start):
        raise ApiRuntimeLifecycleError("api_net_loop_start_failed:missing_start_method")

    attempts = (
        lambda: start(net=net, executor=executor),
        lambda: start(
            executor=executor,
            mempool=getattr(executor, "mempool", None),
            net=net,
        ),
        lambda: start(executor=executor, mempool=getattr(executor, "mempool", None)),
        lambda: start(net, executor),
        lambda: start(executor),
        lambda: start(),
    )
    last_exc: Exception | None = None
    for attempt in attempts:
        try:
            result = attempt()
            return False if result is False else True
        except TypeError as exc:
            last_exc = exc
    if last_exc is not None:
        raise last_exc
    raise ApiRuntimeLifecycleError("api_net_loop_start_failed:invalid_start_signature")


def _stop_net_loop(loop: Any) -> None:
    stop = getattr(loop, "stop", None)
    if callable(stop):
        stop()


@asynccontextmanager
async def _lifespan(app: FastAPI):
    executor = getattr(app.state, "executor", None)
    block_loop = None
    net_loop = None
    net = None
    prod_mode = (os.environ.get("WEALL_MODE") or "").strip().lower() == "prod"

    if executor is not None:
        if _truthy_env("WEALL_BLOCK_LOOP_AUTOSTART"):
            if _runtime_dependencies_missing_for_block_loop(executor):
                if prod_mode:
                    raise ApiRuntimeLifecycleError(
                        "api_block_loop_start_failed:missing_runtime_dependencies"
                    )
            else:
                block_loop = _construct_block_loop(executor)
                started = _start_block_loop(block_loop, executor)
                if not started:
                    if prod_mode:
                        raise ApiRuntimeLifecycleError(
                            "api_block_loop_start_failed:start_returned_false"
                        )
                    _stop_block_loop(block_loop)
                    block_loop = None
                else:
                    app.state.block_loop = block_loop

        if _truthy_env("WEALL_NET_LOOP_AUTOSTART"):
            build_mesh = getattr(executor, "build_mesh_node_from_env", None)
            if callable(build_mesh):
                net = build_mesh()
            else:
                net = getattr(executor, "net", None)
                if net is None:
                    net = object()

            net_loop = _construct_net_loop(net, executor)
            started = _start_net_loop(net_loop, net, executor)
            if not started:
                if prod_mode:
                    raise ApiRuntimeLifecycleError(
                        "api_net_loop_start_failed:start_returned_false"
                    )
                _stop_net_loop(net_loop)
                net_loop = None
                net = None
            else:
                app.state.net = net
                app.state.net_node = net
                app.state.net_loop = net_loop

    try:
        yield
    finally:
        try:
            if net_loop is not None:
                _stop_net_loop(net_loop)
        finally:
            if block_loop is not None:
                _stop_block_loop(block_loop)


def create_app(*, boot_runtime: bool) -> FastAPI:
    _enforce_demo_mode_isolation()
    if _truthy_env("WEALL_DISABLE_OPENAPI"):
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
        return JSONResponse(
            status_code=int(exc.status_code),
            content=_api_error_payload(exc),
        )

    app.state.cfg = load_api_config()

    if boot_runtime:
        cfg = load_chain_config()
        if str(os.environ.get("WEALL_MODE", "") or "").strip().lower() == "prod" or str(
            cfg.mode or ""
        ).strip().lower() == "prod":
            validate_runtime_env()
        _enforce_prod_runtime_topology()
        issues = production_bootstrap_issues(cfg)
        if issues:
            raise RuntimeError("Production bootstrap blocked: " + "; ".join(issues))
        app.state.executor = build_executor()
        _persist_startup_authority_contract(app, app.state.executor)
        _enforce_executor_runtime_authority(app.state.executor)
    else:
        app.state.executor = None
        app.state.startup_authority_contract = {}

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
    app.include_router(helper_readiness_router, prefix="/v1")
    _maybe_mount_web(app)

    return app


app = create_app(boot_runtime=_module_app_boot_runtime_default())
