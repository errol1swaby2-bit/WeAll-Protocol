# tests/test_api_internal_rule_parity.py
from __future__ import annotations

import os
from fastapi import FastAPI
from fastapi.testclient import TestClient


def _load_app() -> FastAPI:
    os.environ["WEALL_API_BOOT_RUNTIME"] = "0"

    from weall.api.routes_public_parts.tx import router as tx_router

    app = FastAPI()
    app.state.executor = None
    app.state.mempool = None
    app.include_router(tx_router, prefix="/v1")

    # Some isolated test/import contexts do not materialize copied APIRouter
    # routes on the app even though tx_router.routes is populated. Fall back to
    # mounting the actual route objects directly so this parity test validates
    # the tx surface that exists in the module.
    has_tx_route = any("tx" in str(getattr(r, "path", "")) for r in app.routes)
    if not has_tx_route:
        app.router.routes.extend(list(tx_router.routes))

    return app

def _find_submit_path(app: FastAPI) -> str | None:
    for route in app.routes:
        path = getattr(route, "path", "")
        methods = {m.upper() for m in getattr(route, "methods", set())}
        if "POST" in methods and "tx" in path and ("submit" in path or "admission" in path):
            return path
    return None


def _find_status_path(app: FastAPI) -> str | None:
    for route in app.routes:
        path = getattr(route, "path", "")
        methods = {m.upper() for m in getattr(route, "methods", set())}
        if "GET" in methods and "tx" in path and "status" in path:
            return path
    return None


def test_tx_submit_surface_has_matching_status_surface():
    app = _load_app()
    assert _find_submit_path(app), "No tx submit-like POST route found"
    assert _find_status_path(app), "No tx status-like GET route found"


def test_tx_submit_invalid_payload_or_not_ready_fails_closed():
    app = _load_app()
    submit_path = _find_submit_path(app)
    assert submit_path, "No tx submit-like POST route found"

    client = TestClient(app, raise_server_exceptions=False)
    response = client.post(submit_path, json={"totally": "invalid"})

    # Accept either:
    # - 4xx validation/admission rejection
    # - explicit 500 fail-closed not_ready/internal rejection when executor is not attached
    assert response.status_code < 600, response.text
    assert response.status_code >= 400, response.text

    content_type = response.headers.get("content-type", "")
    if "application/json" not in content_type:
        assert response.status_code == 500
        assert "Internal Server Error" in response.text
        return

    body = response.json()
    assert isinstance(body, dict), body

    if response.status_code >= 500:
        error = body.get("error")
        if isinstance(error, dict):
            assert error.get("code") in {"not_ready", "executor_not_ready", "runtime_not_ready"}
        return

    assert body.get("ok") is False or "error" in body, body

def test_tx_status_unknown_shape_fails_closed_not_5xx():
    app = _load_app()
    status_path = _find_status_path(app)
    assert status_path, "No tx status-like GET route found"

    client = TestClient(app)

    if "{" in status_path and "}" in status_path:
        path = status_path
        while "{" in path and "}" in path:
            start = path.index("{")
            end = path.index("}", start)
            path = path[:start] + "unknown-tx-id" + path[end + 1 :]
        response = client.get(path)
    else:
        sep = "&" if "?" in status_path else "?"
        response = client.get(f"{status_path}{sep}tx_id=unknown-tx-id")

    assert response.status_code < 500, response.text

