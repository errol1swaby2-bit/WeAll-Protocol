"""Bounded, read-only AST cues for PR62 account-field review.

This is NOT executable transaction causality, a data-flow proof, or normative
authority. All reported fields are syntactic MAY-write candidates.
"""
from __future__ import annotations

import ast
import hashlib
import re
from collections import deque
from pathlib import Path
from typing import Any

from weall_change_gate import ContractError

MAX_SOURCE_BYTES = 2_000_000
MAX_LOCAL_FUNCTIONS = 40
MAX_LOCAL_DEPTH = 4
SHA256 = re.compile(r"[0-9a-f]{64}\Z")


def _require(condition: bool, why: str) -> None:
    if not condition:
        raise ContractError(why)


def _literal_key(node: ast.AST) -> str:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return "<dynamic-key>"


class _AccountFieldProbe(ast.NodeVisitor):
    """Source-order aliases; control-flow joins and callbacks are unresolved."""

    def __init__(self, function: str):
        self.function = function
        self.aliases: dict[str, tuple[str, ...]] = {"state": ()}
        self.writes: list[dict[str, Any]] = []

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        # A nested function may never execute; do not visit its body.
        return

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        return

    def _path(self, node: ast.AST) -> tuple[str, ...] | None:
        if isinstance(node, ast.Name):
            return self.aliases.get(node.id)
        if isinstance(node, ast.Subscript):
            base = self._path(node.value)
            return (*base, _literal_key(node.slice)) if base is not None else None
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            if node.func.attr in {"get", "setdefault"}:
                base = self._path(node.func.value)
                if base is not None:
                    return (*base, _literal_key(node.args[0])) if node.args else (
                        *base, "<dynamic-key>"
                    )
        return None

    def _write(self, path: tuple[str, ...] | None, line: int, form: str) -> None:
        if not path or path[0] != "accounts":
            return
        # A root accounts assignment, account-map mutation, and nested account
        # field mutation are different review categories. No absence claims.
        category = (
            "ACCOUNT_ROOT_OR_MAP"
            if len(path) <= 2
            else "ACCOUNT_FIELD_CANDIDATE"
        )
        self.writes.append(
            {
                "source_function": self.function,
                "line": line,
                "account_path": list(path),
                "field": path[2] if len(path) >= 3 else "<account-map-or-record>",
                "category": category,
                "write_form": form,
                "status": "STATIC_SOURCE_ORDER_ALIAS_CANDIDATE_NOT_EXECUTION_PROOF",
            }
        )

    def visit_Assign(self, node: ast.Assign) -> None:
        self.visit(node.value)
        candidate = self._path(node.value)
        for target in node.targets:
            if isinstance(target, ast.Name):
                if candidate is not None:
                    self.aliases[target.id] = candidate
                else:
                    self.aliases.pop(target.id, None)
            self.visit(target)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
        if node.value is not None:
            self.visit(node.value)
        if isinstance(node.target, ast.Name):
            candidate = self._path(node.value) if node.value is not None else None
            if candidate is not None:
                self.aliases[node.target.id] = candidate
            else:
                self.aliases.pop(node.target.id, None)
        self.visit(node.target)

    def visit_Subscript(self, node: ast.Subscript) -> None:
        if isinstance(node.ctx, (ast.Store, ast.Del)):
            self._write(
                self._path(node), node.lineno,
                "SUBSCRIPT_DELETE" if isinstance(node.ctx, ast.Del) else "SUBSCRIPT_ASSIGN",
            )
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        if isinstance(node.func, ast.Attribute):
            name = node.func.attr
            base = self._path(node.func.value)
            if name in {"setdefault", "pop"} and base is not None:
                self._write(
                    (*base, _literal_key(node.args[0])) if node.args
                    else (*base, "<dynamic-key>"),
                    node.lineno, "MAP_MUTATOR_" + name.upper(),
                )
            elif name in {"update", "clear", "popitem", "append", "extend"}:
                self._write(base, node.lineno, "MUTATOR_" + name.upper())
        self.generic_visit(node)


def scan_account_field_review(
    repo: Path, open_triage: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    """Exact-byte-checked, bounded same-file call-graph REVIEW cues only."""
    parsed: dict[str, tuple[dict[str, ast.FunctionDef], str]] = {}
    results = []
    for item in open_triage:
        path = item["source_path"]
        expected = item["source_file_sha256"]
        relative = Path(path)
        _require(
            isinstance(path, str) and not relative.is_absolute()
            and ".." not in relative.parts
            and path.startswith("Weall-Protocol/src/weall/runtime/")
            and relative.suffix == ".py"
            and bool(SHA256.fullmatch(str(expected))),
            "unmatched_field_trace_invalid_source_pin",
        )
        if path not in parsed:
            data = (repo / relative).read_bytes()
            _require(0 < len(data) <= MAX_SOURCE_BYTES, "unmatched_field_trace_size_invalid")
            sha = hashlib.sha256(data).hexdigest()
            _require(sha == expected, "unmatched_field_trace_source_sha_mismatch")
            tree = ast.parse(data, filename=path)
            functions = {
                node.name: node
                for node in tree.body
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
            }
            parsed[path] = (functions, sha)
        functions, actual_sha = parsed[path]
        _require(actual_sha == expected, "unmatched_field_trace_source_sha_mismatch")
        anchor = item.get("source_function")
        _require(isinstance(anchor, str) and anchor in functions, "unmatched_field_anchor_absent")
        queue = deque([(anchor, 0)])
        visited: set[str] = set()
        evidence: list[dict[str, Any]] = []
        truncated = False
        while queue:
            name, depth = queue.popleft()
            if name in visited:
                continue
            if depth > MAX_LOCAL_DEPTH or len(visited) >= MAX_LOCAL_FUNCTIONS:
                truncated = True
                continue
            fn = functions[name]
            visited.add(name)
            probe = _AccountFieldProbe(name)
            # We only infer aliases named "state"; helper state handoff is NOT
            # checked by this lightweight local-name call graph.
            for statement in fn.body:
                probe.visit(statement)
            for w in probe.writes:
                evidence.append({**w, "same_file_call_depth": depth})
            for call in ast.walk(fn):
                if isinstance(call, ast.Call) and isinstance(call.func, ast.Name):
                    callee = call.func.id
                    if callee in functions and callee not in visited:
                        queue.append((callee, depth + 1))
        evidence.sort(key=lambda x: (
            x["source_function"], x["line"], x["field"], x["write_form"]
        ))
        # Avoid duplicate identical candidate rows from syntactic revisits.
        uniq = {(
            x["source_function"], x["line"], tuple(x["account_path"]), x["write_form"]
        ): x for x in evidence}
        evidence = sorted(uniq.values(), key=lambda x: (
            x["source_function"], x["line"], x["field"], x["write_form"]
        ))
        results.append({
            "review_key": item["review_key"],
            "source_path": path,
            "source_commit": item["source_commit"],
            "source_file_sha256": actual_sha,
            "anchor_function": anchor,
            "state_root": item["state_root"],
            "same_file_functions_visited": sorted(visited),
            "same_file_local_trace_truncated": truncated,
            "field_write_candidates": evidence,
            "field_write_candidate_count": len(evidence),
            "unknown_or_external_helper_effects_unproven": True,
            "status": "SOURCE_ORDER_STATIC_FIELD_CUES_NOT_TX_CAUSALITY_OR_AUTHORITY",
            "constitutional_authorization": "NOT_ESTABLISHED",
        })
    return results
