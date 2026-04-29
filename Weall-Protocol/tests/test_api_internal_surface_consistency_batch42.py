# tests/test_api_internal_surface_consistency_batch42.py
from __future__ import annotations

from collections import defaultdict

from fastapi import FastAPI


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


def test_no_duplicate_public_route_method_path_pairs_batch42():
    app = _load_app()
    seen: dict[tuple[str, str], int] = defaultdict(int)

    for route in app.routes:
        path = getattr(route, "path", "")
        methods = {m.upper() for m in getattr(route, "methods", set())}
        for method in methods:
            if method in {"HEAD", "OPTIONS"}:
                continue
            if path.startswith("/v1"):
                seen[(method, path)] += 1

    duplicates = {k: v for k, v in seen.items() if v > 1}
    assert not duplicates, duplicates


def test_v1_routes_use_absolute_versioned_prefix_batch42():
    app = _load_app()
    bad = []

    for route in app.routes:
        path = getattr(route, "path", "")
        if "v1" in path and not path.startswith("/v1"):
            bad.append(path)

    assert not bad, bad


def test_tx_routes_do_not_mix_submit_and_status_on_same_method_path_batch42():
    app = _load_app()

    overlapping = []
    for route in app.routes:
        path = getattr(route, "path", "")
        methods = {m.upper() for m in getattr(route, "methods", set())}
        if "/v1" in path and "tx" in path and "submit" in path and "status" in path:
            overlapping.append((path, sorted(methods)))

    assert not overlapping, overlapping
