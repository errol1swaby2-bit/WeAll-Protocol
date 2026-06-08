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


def test_api_contract_map_is_generated_and_complete_batch494() -> None:
    payload = json.loads(MAP_PATH.read_text(encoding="utf-8"))
    routes = payload["routes"]

    assert payload["schema"] == "weall.api_contract_map.v1_5"
    assert payload["route_prefix"] == "/v1"
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


def test_api_contract_generator_is_deterministic_batch494() -> None:
    before = MAP_PATH.read_text(encoding="utf-8")
    result = subprocess.run(
        [sys.executable, "scripts/gen_api_contract_map.py"],
        cwd=ROOT,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    after = MAP_PATH.read_text(encoding="utf-8")
    assert result.returncode == 0, result.stdout + result.stderr
    assert before == after
