"""Provisional A01 route-identity evidence, not a V2 semantic approval.

The registered public-lobby projection has a stable code-bound identity.
This test deliberately does not accept/refresh the route semantic-review digest.
"""

from __future__ import annotations

import ast
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ROUTE_PATH = "GET /v1/public-lobby/comments"
IMPLEMENTATION = "src/weall/api/routes_public_parts/content.py"
FUNCTION = "public_lobby_comments"
CANONICAL_KEY = f"{ROUTE_PATH}|{IMPLEMENTATION}|{FUNCTION}"


def test_public_lobby_route_identity_is_unique_and_not_tombstoned() -> None:
    registry = json.loads((ROOT / "specs/v2/source/stable_ids.json").read_text(encoding="utf-8"))
    expected = "ROUTE-" + hashlib.sha256(CANONICAL_KEY.encode("utf-8")).hexdigest()[:16].upper()
    matches = [
        row
        for row in registry["entries"]
        if row.get("kind") == "route" and row.get("canonical_key") == CANONICAL_KEY
    ]
    assert len(matches) == 1
    assert matches[0]["stable_id"] == expected
    assert matches[0]["status"] == "active"
    assert matches[0]["aliases"] == []
    assert sum(row.get("stable_id") == expected for row in registry["entries"]) == 1
    assert not any(row.get("stable_id") == expected for row in registry.get("tombstones", []))


def test_public_lobby_route_identity_matches_real_read_handler() -> None:
    tree = ast.parse((ROOT / IMPLEMENTATION).read_text(encoding="utf-8"))
    funcs = [
        node
        for node in tree.body
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == FUNCTION
    ]
    assert len(funcs) == 1
    handler = funcs[0]
    decorators = [
        node
        for node in handler.decorator_list
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and isinstance(node.func.value, ast.Name)
        and node.func.value.id == "router"
        and node.func.attr == "get"
    ]
    assert len(decorators) == 1
    assert isinstance(decorators[0].args[0], ast.Constant)
    assert decorators[0].args[0].value == "/public-lobby/comments"
    called = {
        node.func.id
        for node in ast.walk(handler)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
    }
    assert {
        "_required_public_lobby_snapshot",
        "_comments",
        "_comment_visible",
        "_cursor_unpack",
        "_cursor_pack",
    } <= called
    # The live route must NOT silently downgrade unavailable backend state
    # to an empty success by using the legacy compatibility _snapshot helper.
    assert "_snapshot" not in called
    assert "_required_public_lobby_snapshot" in called
    # Structural read-contract check only: API runtime, redaction and auth still need review.
    assert "require_account_session" not in called
