# tests/test_api_internal_rule_parity_batch42.py
from __future__ import annotations

from fastapi import FastAPI
from fastapi.testclient import TestClient


def _load_app() -> FastAPI:
    import weall.api.app as app_mod

    for name in ("app", "api", "application"):
        value = getattr(app_mod, name, None)
        if isinstance(value, FastAPI):
            return value

    for name in ("create_app", "build_app", "make_app", "get_app"):
        fn = getattr(app_mod, name, None)
        if callable(fn):
            try:
                value = fn()
            except TypeError:
                continue
            if isinstance(value, FastAPI):
                return value

    raise AssertionError("Could not locate FastAPI app in weall.api.app")


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


def test_tx_submit_surface_has_matching_status_surface_batch42():
    app = _load_app()
    assert _find_submit_path(app), "No tx submit-like POST route found"
    assert _find_status_path(app), "No tx status-like GET route found"


def test_tx_submit_invalid_payload_or_not_ready_fails_closed_batch42():
    app = _load_app()
    submit_path = _find_submit_path(app)
    assert submit_path, "No tx submit-like POST route found"

    client = TestClient(app)
    response = client.post(submit_path, json={"totally": "invalid"})

    # Accept either:
    # - 4xx validation/admission rejection
    # - explicit 500 fail-closed "not_ready" rejection when executor is not attached
    assert response.status_code < 600, response.text
    assert response.status_code >= 400, response.text

    body = response.json()
    assert isinstance(body, dict), body
    assert body.get("ok") is False, body

    error = body.get("error")
    assert isinstance(error, dict), body
    code = error.get("code")
    assert isinstance(code, str) and code, body

    if response.status_code >= 500:
        assert code == "not_ready", body


def test_tx_status_unknown_shape_fails_closed_not_5xx_batch42():
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

