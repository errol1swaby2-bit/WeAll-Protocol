#!/usr/bin/env python3
from __future__ import annotations

import ast
import hashlib
import json
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
ROUTE_DIR = ROOT / "src" / "weall" / "api" / "routes_public_parts"
OUT = ROOT / "generated" / "api_contract_map_v1_5.json"

HTTP_METHODS = {"get", "post", "put", "delete", "patch"}


def _literal(node: ast.AST) -> Any:
    if isinstance(node, ast.Constant):
        return node.value
    if isinstance(node, ast.List):
        return [_literal(elt) for elt in node.elts]
    if isinstance(node, ast.Tuple):
        return [_literal(elt) for elt in node.elts]
    return None


def _route_auth(method: str, path: str, module: str, function: str) -> str:
    p = path.lower()
    m = method.upper()
    if m == "GET":
        return "public_read_redacted_snapshot"
    if "/tx/submit" in p:
        return "signed_canonical_tx_required"
    if "/session/login" in p:
        return "local_session_login_request"
    if "/observer/edge" in p or "relay" in module or "/sync/" in p:
        return "node_or_observer_route_specific_authority"
    if "demo" in module:
        return "dev_or_controlled_demo_only"
    return "route_specific_signed_or_local_authority"


def _idempotency(method: str, path: str) -> str:
    m = method.upper()
    p = path.lower()
    if m == "GET":
        return "safe_read_no_state_mutation"
    if "/tx/submit" in p:
        return "tx_id_replay_and_confirmed_status_dedupe"
    if "/sync/" in p or "/observer/edge" in p:
        return "route_specific_replay_or_cursor_guard"
    return "route_specific_no_general_idempotency_claim"


def _cache_policy(method: str) -> str:
    if method.upper() == "GET":
        return "no_store_dynamic_public_read_model_unless_route_overrides"
    return "no_store_mutation_or_submission_route"


def _route_contract(path: Path) -> list[dict[str, Any]]:
    rel = path.relative_to(ROOT).as_posix()
    module = path.stem
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=rel)
    contracts: list[dict[str, Any]] = []
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        for deco in node.decorator_list:
            if not isinstance(deco, ast.Call):
                continue
            func = deco.func
            if not (
                isinstance(func, ast.Attribute)
                and isinstance(func.value, ast.Name)
                and func.value.id == "router"
                and func.attr in HTTP_METHODS
            ):
                continue
            route_path = ""
            if deco.args:
                value = _literal(deco.args[0])
                route_path = str(value or "")
            method = func.attr.upper()
            full_path = "/v1" + route_path
            kwargs = {kw.arg: _literal(kw.value) for kw in deco.keywords if kw.arg}
            tags = kwargs.get("tags") or [module]
            if not isinstance(tags, list):
                tags = [str(tags)]
            route_id = hashlib.sha256(f"{method} {full_path} {rel}:{node.name}".encode("utf-8")).hexdigest()[:16]
            contracts.append(
                {
                    "route_id": route_id,
                    "method": method,
                    "path": full_path,
                    "route_path_without_v1_prefix": route_path,
                    "module": module,
                    "function": node.name,
                    "source": rel,
                    "source_lineno": int(getattr(node, "lineno", 0) or 0),
                    "tags": [str(t) for t in tags if str(t)],
                    "summary": str(kwargs.get("summary") or ""),
                    "auth": _route_auth(method, full_path, module, node.name),
                    "error_model": "standard_api_error_envelope_or_route_specific_ok_false_payload",
                    "rate_limit_policy": "global_api_rate_limit_and_request_size_middleware; stricter route gates may apply",
                    "idempotency": _idempotency(method, full_path),
                    "cache_policy": _cache_policy(method),
                    "launch_matrix_binding": "see generated/launch_disabled_matrix_v1_5.json",
                    "truth_boundary": "Contract inventory only; runtime code remains the authority for validation and mutation.",
                }
            )
    return contracts


def main() -> int:
    routes: list[dict[str, Any]] = []
    for path in sorted(ROUTE_DIR.glob("*.py")):
        if path.name == "common.py" or path.name == "__init__.py":
            continue
        routes.extend(_route_contract(path))
    routes.sort(key=lambda r: (r["path"], r["method"], r["source"], r["function"]))
    by_domain: dict[str, int] = {}
    for route in routes:
        domain = str(route["module"])
        by_domain[domain] = by_domain.get(domain, 0) + 1
    payload = {
        "schema": "weall.api_contract_map.v1_5",
        "version": "2026-06-v1.5-public-readiness-batch",
        "route_prefix": "/v1",
        "route_count": len(routes),
        "by_domain": dict(sorted(by_domain.items())),
        "required_metadata_fields": [
            "method",
            "path",
            "auth",
            "error_model",
            "rate_limit_policy",
            "idempotency",
            "cache_policy",
        ],
        "truth_boundary": "Generated static inventory for reviewer/API-readiness audit; not a replacement for route-level runtime tests.",
        "routes": routes,
    }
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"wrote {OUT.relative_to(ROOT)} ({len(routes)} routes)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
