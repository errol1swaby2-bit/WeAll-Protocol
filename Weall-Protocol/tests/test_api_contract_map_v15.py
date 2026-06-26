from __future__ import annotations

import ast
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MAP_PATH = ROOT / "generated" / "api_contract_map_v1_5.json"
REQUIRED_FIELDS = {
    "method",
    "path",
    "auth",
    "error_model",
    "rate_limit_policy",
    "idempotency",
    "cache_policy",
}


def _decorated_route_count() -> int:
    count = 0
    for path in (ROOT / "src/weall/api/routes_public_parts").glob("*.py"):
        if path.name in {"common.py", "__init__.py"}:
            continue
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            for deco in node.decorator_list:
                if (
                    isinstance(deco, ast.Call)
                    and isinstance(deco.func, ast.Attribute)
                    and isinstance(deco.func.value, ast.Name)
                    and deco.func.value.id == "router"
                    and deco.func.attr in {"get", "post", "put", "delete", "patch"}
                ):
                    count += 1
    return count


def _routes_by_key() -> dict[str, dict]:
    payload = json.loads(MAP_PATH.read_text(encoding="utf-8"))
    return {f"{route['method']} {route['path']}": route for route in payload["routes"]}


def test_api_contract_map_is_generated_and_complete_batch494() -> None:
    payload = json.loads(MAP_PATH.read_text(encoding="utf-8"))
    routes = payload["routes"]

    assert payload["schema"] == "weall.api_contract_map.v1_5"
    assert payload["route_prefix"] == "/v1"
    assert payload["metadata_source"] == "specs/api_contracts/v1_5_route_metadata.json"
    assert payload["route_count"] == len(routes) == _decorated_route_count()
    assert payload["route_count"] >= 120

    ids = set()
    for route in routes:
        assert REQUIRED_FIELDS.issubset(route.keys())
        assert route["method"] in {"GET", "POST", "PUT", "DELETE", "PATCH"}
        assert str(route["path"]).startswith("/v1/")
        assert str(route["auth"]).strip()
        assert str(route["error_model"]).strip()
        assert str(route["rate_limit_policy"]).strip()
        assert str(route["idempotency"]).strip()
        assert str(route["cache_policy"]).strip()
        ids.add(route["route_id"])
    assert len(ids) == len(routes)


def test_api_contract_generator_is_deterministic_and_checkable_batch494() -> None:
    before = MAP_PATH.read_text(encoding="utf-8")
    result = subprocess.run(
        [sys.executable, "scripts/gen_api_contract_map.py", "--check"],
        cwd=ROOT,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    after = MAP_PATH.read_text(encoding="utf-8")
    assert result.returncode == 0, result.stdout + result.stderr
    assert before == after


def test_api_contract_auth_metadata_does_not_overclaim_sensitive_get_routes_batch494() -> None:
    routes = _routes_by_key()

    assert "GET /v1/" + "mess" + "ages/threads" not in routes
    assert routes["GET /v1/activity/notices"]["auth"] == "public_read_public_activity_notices"

    for key in [
        "GET /v1/reviewer/artifacts",
        "GET /v1/reviewer/artifacts/bundle",
        "GET /v1/reviewer/artifacts/manifest",
    ]:
        assert routes[key]["auth"] == "reviewer_artifacts_env_gated_public_when_enabled"
        assert "public_read_redacted_snapshot" not in routes[key]["auth"]
        assert "metadata_source" in routes[key]

    assert routes["GET /v1/status/launch-matrix"]["auth"] == "public_read_launch_capability_truth_boundary"
