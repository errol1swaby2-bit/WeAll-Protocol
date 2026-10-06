from __future__ import annotations

import json
from collections import Counter
from pathlib import Path

from weall.api import routes_nodes
from weall.api.routes_public_parts.nodes import router as nodes_router


ROOT = Path(__file__).resolve().parents[1]
NODE_ROUTE_KEYS = {
    ("GET", "/v1/nodes"),
    ("GET", "/v1/nodes/known"),
    ("GET", "/v1/nodes/seeds"),
    ("GET", "/v1/nodes/validators"),
}
NODE_CHILD_ROUTE_KEYS = {
    ("GET", "/nodes"),
    ("GET", "/nodes/known"),
    ("GET", "/nodes/seeds"),
    ("GET", "/nodes/validators"),
}


def _node_router_rows() -> list[tuple[str, str, str]]:
    rows: list[tuple[str, str, str]] = []
    for route in nodes_router.routes:
        path = str(getattr(route, "path", "") or "")
        methods = getattr(route, "methods", set()) or set()
        endpoint = getattr(route, "endpoint", None)
        module = str(getattr(endpoint, "__module__", ""))
        for method in sorted(str(m).upper() for m in methods):
            if method in {"HEAD", "OPTIONS"}:
                continue
            rows.append((method, path, module))
    return rows


def _generated_route_map() -> dict:
    return json.loads(
        (ROOT / "generated" / "v2" / "route_contract_map.json").read_text(encoding="utf-8")
    )


def test_a01_f003_routes_nodes_is_helper_only_not_a_shadow_router() -> None:
    assert not hasattr(routes_nodes, "router")
    source = (ROOT / "src" / "weall" / "api" / "routes_nodes.py").read_text(encoding="utf-8")
    assert "@router." not in source
    assert "APIRouter" not in source


def test_a01_f003_node_routes_have_one_mounted_canonical_implementation() -> None:
    declared = _node_router_rows()
    counts = Counter((method, path) for method, path, _module in declared)

    for key in NODE_CHILD_ROUTE_KEYS:
        assert counts[key] == 1

    node_modules = {
        (method, path): module
        for method, path, module in declared
        if (method, path) in NODE_CHILD_ROUTE_KEYS
    }
    assert set(node_modules.values()) == {"weall.api.routes_public_parts.nodes"}

    routes_public_source = (
        ROOT / "src" / "weall" / "api" / "routes_public.py"
    ).read_text(encoding="utf-8")
    mount = 'public_router.include_router(nodes_router, prefix="/v1", tags=["nodes"])'
    assert routes_public_source.count(mount) == 1


def test_a01_f003_generated_route_inventory_has_no_shadow_implementations() -> None:
    payload = _generated_route_map()
    rows = payload["routes"]

    assert payload["route_count"] == 159
    assert payload["unique_method_path_count"] == 159
    assert payload["duplicate_route_implementation_count"] == 0
    assert len(rows) == 159
    assert not [row for row in rows if row.get("duplicate_route_key")]

    # The retired helper module must not appear as a decorated V2 route source.
    assert not [
        row
        for row in rows
        if str(row["implementation_source"]["path"])
        == "src/weall/api/routes_nodes.py"
    ]


def test_a01_f003_generated_node_authority_points_only_to_mounted_wrapper_module() -> None:
    rows = _generated_route_map()["routes"]
    node_rows = [
        row
        for row in rows
        if (str(row["method"]).upper(), str(row["path"])) in NODE_ROUTE_KEYS
    ]

    assert len(node_rows) == 4
    assert {
        (str(row["method"]).upper(), str(row["path"])) for row in node_rows
    } == NODE_ROUTE_KEYS
    assert {
        str(row["implementation_source"]["path"]) for row in node_rows
    } == {"src/weall/api/routes_public_parts/nodes.py"}
