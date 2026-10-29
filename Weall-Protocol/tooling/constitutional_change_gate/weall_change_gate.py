#!/usr/bin/env python3
"""WeAll transaction-to-authority change impact inventory (candidate, not consensus code).

Stdlib only. It deliberately fails closed on incomplete canonical contracts,
unknown source files, unsigned evidence claims, and unreviewed authority effects.
It never writes to a user repository, node ledger, or GitHub.
"""

from __future__ import annotations

import argparse
import ast
import csv
import hashlib
import json
import re
import subprocess
import sys
from collections import defaultdict
from pathlib import Path
from typing import Any

PREFIX = Path("Weall-Protocol")
RUNTIME = PREFIX / "src/weall/runtime"
INDEX = PREFIX / "generated/tx_index.json"
POLICY_ROOT = Path(__file__).resolve().parent / "policies"
SHA_RE = re.compile(r"^[0-9a-f]{40}$")


class ContractError(ValueError):
    pass


def canonical_bytes(obj: Any) -> bytes:
    return (json.dumps(obj, indent=2, sort_keys=True, ensure_ascii=False) + "\n").encode()


def digest(p: Path) -> str:
    return hashlib.sha256(p.read_bytes()).hexdigest()


def read_json(p: Path) -> Any:
    return json.loads(p.read_text(encoding="utf-8"))


def atomic_write(p: Path, payload: bytes) -> None:
    p.parent.mkdir(parents=True, exist_ok=True)
    # Output is always in a user-chosen artifact directory, never the repository.
    p.write_bytes(payload)


def module_path(module: str) -> Path:
    if not module.startswith("weall."):
        raise ContractError("unsupported_import:" + module)
    return PREFIX / "src" / Path(*module.split(".")).with_suffix(".py")


class ASTResolver:
    def __init__(self, repo: Path):
        self.repo = repo
        self.cache: dict[str, ast.Module] = {}
        self.defs: dict[str, dict[str, ast.AST]] = {}
        self.imports: dict[str, dict[str, tuple[str, str]]] = {}

    def tree(self, module: str) -> ast.Module:
        if module in self.cache:
            return self.cache[module]
        path = self.repo / module_path(module)
        if not path.is_file():
            raise ContractError(f"missing_module:{module}:{path}")
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        self.cache[module] = tree
        sym: dict[str, ast.AST] = {}
        imports: dict[str, tuple[str, str]] = {}
        for n in tree.body:
            if isinstance(n, ast.ImportFrom) and n.module:
                for a in n.names:
                    imports[a.asname or a.name] = (n.module, a.name)
            elif isinstance(n, ast.Assign):
                for t in n.targets:
                    if isinstance(t, ast.Name):
                        sym[t.id] = n.value
            elif isinstance(n, ast.AnnAssign) and isinstance(n.target, ast.Name) and n.value:
                sym[n.target.id] = n.value
        self.defs[module] = sym
        self.imports[module] = imports
        return tree

    def val(
        self, node: ast.AST, module: str, seen: frozenset[tuple[str, str]] = frozenset()
    ) -> Any:
        if isinstance(node, ast.Constant):
            return node.value
        if isinstance(node, (ast.Set, ast.List, ast.Tuple)):
            return [self.val(v, module, seen) for v in node.elts]
        if isinstance(node, ast.Dict):
            return {
                self.val(k, module, seen): self.val(v, module, seen)
                for k, v in zip(node.keys, node.values, strict=False)
            }
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id in {"frozenset", "set", "tuple", "list"}
            and len(node.args) == 1
            and not node.keywords
        ):
            return self.val(node.args[0], module, seen)
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.BitOr):
            return sorted(
                set(self.val(node.left, module, seen)) | set(self.val(node.right, module, seen))
            )
        if isinstance(node, ast.Name):
            self.tree(module)
            key = (module, node.id)
            if key in seen:
                raise ContractError("circular_symbol:" + repr(key))
            if node.id in self.defs[module]:
                return self.val(self.defs[module][node.id], module, seen | {key})
            if node.id in self.imports[module]:
                other, symbol = self.imports[module][node.id]
                self.tree(other)
                if symbol not in self.defs[other]:
                    raise ContractError(f"unresolved_import:{other}:{symbol}")
                return self.val(self.defs[other][symbol], other, seen | {key})
        raise ContractError(f"unsupported_static_expression:{module}:{ast.dump(node)[:140]}")

    def schema_models(self) -> dict[str, str]:
        mod = "weall.runtime.tx_schema"
        self.tree(mod)
        node = self.defs[mod].get("TX_PAYLOADS")
        if not isinstance(node, ast.Dict):
            raise ContractError("missing_TX_PAYLOADS_dict")
        out: dict[str, str] = {}
        for k, v in zip(node.keys, node.values, strict=False):
            if (
                not isinstance(k, ast.Constant)
                or not isinstance(k.value, str)
                or not isinstance(v, ast.Name)
            ):
                raise ContractError("non_static_schema_mapping")
            if k.value in out:
                raise ContractError("duplicate_schema_tx:" + k.value)
            # Do not confuse an unbound or deleted class name with a verified schema model.
            if (
                not any(
                    isinstance(x, ast.ClassDef) and x.name == v.id for x in self.cache[mod].body
                )
                and v.id not in self.imports[mod]
            ):
                raise ContractError("undefined_payload_model:" + v.id)
            out[k.value] = v.id
        return out

    def routed_functions(
        self, handler_module: str, handler_fn: str, allowed_types: list[str]
    ) -> dict[str, dict[str, Any]]:
        """Conservative AST anchors for obvious `if t == TX: return helper(...)` routes.

        An anchor is NOT a proof that all behavior resides in the helper;
        callbacks, schedulers and state side effects remain separately unmapped.
        """
        tree = self.tree(handler_module)
        fn = next(
            (n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == handler_fn), None
        )
        if fn is None:
            return {}
        candidates: dict[str, set[tuple[str, int]]] = defaultdict(set)
        for case in ast.walk(fn):
            if not isinstance(case, ast.If):
                continue
            expr = case.test
            if (
                not isinstance(expr, ast.Compare)
                or len(expr.ops) != 1
                or len(expr.comparators) != 1
            ):
                continue
            if not isinstance(expr.left, ast.Name) or expr.left.id not in {"t", "tx", "tx_type"}:
                continue
            cmp = expr.comparators[0]
            values: list[str] = []
            if (
                isinstance(expr.ops[0], ast.Eq)
                and isinstance(cmp, ast.Constant)
                and isinstance(cmp.value, str)
            ):
                values = [cmp.value]
            if isinstance(expr.ops[0], ast.In) and isinstance(cmp, (ast.Set, ast.Tuple, ast.List)):
                values = [
                    v.value
                    for v in cmp.elts
                    if isinstance(v, ast.Constant) and isinstance(v.value, str)
                ]
            for op in case.body:
                if not isinstance(op, ast.Return) or not isinstance(op.value, ast.Call):
                    continue
                callee = op.value.func
                if not isinstance(callee, ast.Name):
                    continue
                for value in values:
                    if value in allowed_types:
                        candidates[value].add((callee.id, case.lineno))
        return {
            t: {
                "routed_function": next(iter(v))[0],
                "route_line": next(iter(v))[1],
                "route_status": "STATIC_DIRECT_RETURN_ANCHOR_ONLY",
            }
            for t, v in candidates.items()
            if len(v) == 1
        }

    def handlers(self) -> dict[str, list[dict[str, str]]]:
        mod = "weall.runtime.tx_contracts"
        self.tree(mod)
        node = self.defs[mod].get("HANDLER_REGISTRY")
        if not isinstance(node, ast.Tuple):
            raise ContractError("missing_HANDLER_REGISTRY_tuple")
        output: dict[str, list[dict[str, str]]] = defaultdict(list)
        for ent in node.elts:
            if not isinstance(ent, ast.Tuple) or len(ent.elts) != 3:
                raise ContractError("unknown_handler_entry")
            label, fn, type_expr = ent.elts
            if not isinstance(label, ast.Constant) or not isinstance(fn, ast.Name):
                raise ContractError("unknown_handler_metadata")
            if fn.id not in self.imports[mod]:
                raise ContractError("unresolved_handler_import:" + fn.id)
            impl_module, impl_fn = self.imports[mod][fn.id]
            # Verify entrypoint exists as a real function in that module.
            tree = self.tree(impl_module)
            if not any(
                isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and n.name == impl_fn
                for n in tree.body
            ):
                raise ContractError("missing_apply_function:" + impl_fn)
            values = self.val(type_expr, mod)
            if not isinstance(values, list):
                raise ContractError("non_static_handler_types:" + str(label.value))
            routes = self.routed_functions(impl_module, impl_fn, values)
            for tx in values:
                if not isinstance(tx, str):
                    raise ContractError("invalid_handler_tx")
                output[tx].append(
                    {
                        "handler": str(label.value),
                        "source_path": str(module_path(impl_module)),
                        "entrypoint": impl_fn,
                        "routed_function": routes.get(tx, {}).get("routed_function"),
                        "route_line": routes.get(tx, {}).get("route_line"),
                        "route_status": routes.get(tx, {}).get("route_status", "NOT_DETERMINED"),
                    }
                )
        return output


def extract_routes(repo: Path) -> dict[str, dict[str, Any]]:
    idx_path = repo / INDEX
    raw = read_json(idx_path)
    entries, by_name, by_id = raw.get("tx_types"), raw.get("by_name"), raw.get("by_id")
    if (
        not isinstance(entries, list)
        or not isinstance(by_name, dict)
        or not isinstance(by_id, dict)
    ):
        raise ContractError("malformed_canonical_index")
    resolver = ASTResolver(repo)
    models = resolver.schema_models()
    handlers = resolver.handlers()
    rows = {}
    all_names = []
    ids = []
    for i, e in enumerate(entries):
        if (
            not isinstance(e, dict)
            or not isinstance(e.get("name"), str)
            or not isinstance(e.get("id"), str)
        ):
            raise ContractError(f"malformed_entry_at:{i}")
        name = e["name"]
        all_names.append(name)
        ids.append(e["id"])
        if by_name.get(name) != i:
            raise ContractError("by_name_index_mismatch:" + name)
        hs = handlers.get(name, [])
        if len(hs) != 1:
            raise ContractError(f"handler_cardinality:{name}:{len(hs)}")
        if name not in models:
            raise ContractError("schema_missing:" + name)
        numeric_aliases = sorted(k for k, v in by_id.items() if v == i)
        row = {
            "tx_type": name,
            "canonical_id": e["id"],
            "repository_position": i,
            "repository_numeric_keys": numeric_aliases,
            "domain": e.get("domain", ""),
            "origin": e.get("origin", ""),
            "context": e.get("context", ""),
            "system_only": bool(e.get("system_only", False)),
            "receipt_only": bool(e.get("receipt_only", False)),
            "parent_tx_type": e.get("parent_tx_type", ""),
            "declared_gates": e.get("gates", {}),
            "declared_subject_gate": e.get("subject_gate"),
            "signer_authority_contract": None,
            "poh_gate": None,
            "role_gate": None,
            "conflict_rules": None,
            "activation_status": None,
            "receipt_contract": None,
            "payload_model": models[name],
            "payload_model_source": str(RUNTIME / "tx_schema.py"),
            **hs[0],
            "authority_policy_status": "UNADJUDICATED",
            "state_reads": None,
            "state_writes": None,
            "system_followups": None,
            "failure_codes": None,
            "replay_contract": None,
            "api_route": None,
            "frontend_surface": None,
            "acceptance_tests": [],
            "verification_status": "NOT_VERIFIED",
        }
        rows[name] = row
    if len(all_names) != len(set(all_names)) or len(ids) != len(set(ids)):
        raise ContractError("duplicate_name_or_id")
    if set(models) != set(rows):
        raise ContractError(
            "schema_noncanonical_types:" + ",".join(sorted(set(models) - set(rows)))
        )
    if set(handlers) != set(rows):
        raise ContractError(
            "registry_noncanonical_types:" + ",".join(sorted(set(handlers) - set(rows)))
        )
    if set(by_name) != set(rows):
        raise ContractError("by_name_coverage_mismatch")
    # Attach to the repository's EXISTING 236-row contract derivative instead
    # of silently creating a competing authoritative matrix.
    existing_map = repo / PREFIX / "generated/tx_contract_map.json"
    if existing_map.is_file():
        existing = read_json(existing_map)
        contracts = existing.get("contracts") if isinstance(existing, dict) else None
        if not isinstance(contracts, list):
            raise ContractError("existing_contract_map_invalid")
        lookup: dict[str, dict] = {}
        for ent in contracts:
            if not isinstance(ent, dict) or not isinstance(ent.get("tx_type"), str):
                raise ContractError("existing_contract_map_invalid_row")
            if ent["tx_type"] in lookup:
                raise ContractError("existing_contract_map_duplicate:" + ent["tx_type"])
            lookup[ent["tx_type"]] = ent
        if set(lookup) != set(rows):
            raise ContractError("existing_contract_map_coverage_mismatch")
        for name, row in rows.items():
            ent = lookup[name]
            if (
                ent.get("handler") != row["handler"]
                or not ent.get("schema_covered")
                or ent.get("unsupported")
                or ent.get("claim_count") != 1
            ):
                raise ContractError("existing_contract_map_disagrees:" + name)
            for field in ("domain", "origin", "context"):
                if ent.get(field) != row[field]:
                    raise ContractError(f"existing_contract_map_{field}_mismatch:{name}")
            row["existing_contract_map_status"] = "MATCHED_SOURCE_DERIVATIVE"
    else:
        for row in rows.values():
            row["existing_contract_map_status"] = "ABSENT_UNVERIFIED"

    for k, v in by_id.items():
        if not isinstance(v, int) or v < 0 or v >= len(entries):
            raise ContractError("numeric_alias_invalid:" + k)
    return dict(sorted(rows.items()))


# Non-normative REVIEW TAXONOMY of exact root keys observed by the AST.
# An account/group/dispute write is NOT necessarily an authority change.
# Never use this table to grant, deny, or certify authorization.
AUTHORITY_REVIEW_ROOTS: dict[str, str] = {
    "accounts": "ACCOUNT_ACCESS_OR_IDENTITY_REVIEW",
    "account_recovery": "ACCOUNT_RECOVERY_AUTHORITY_REVIEW",
    "account_sessions": "SESSION_AUTHORITY_REVIEW",
    "poh": "POH_ELIGIBILITY_REVIEW",
    "poh_cases": "POH_ELIGIBILITY_REVIEW",
    "poh_tier2": "POH_ELIGIBILITY_REVIEW",
    "reputation": "REPUTATION_OR_SANCTION_REVIEW",
    "reputations": "REPUTATION_OR_SANCTION_REVIEW",
    "reputation_events": "REPUTATION_OR_SANCTION_REVIEW",
    "governance": "VOTING_OR_PROPOSAL_REVIEW",
    "proposals": "VOTING_OR_PROPOSAL_REVIEW",
    "votes": "VOTING_OR_PROPOSAL_REVIEW",
    "ballots": "VOTING_OR_PROPOSAL_REVIEW",
    "disputes": "DISPUTE_OR_ENFORCEMENT_REVIEW",
    "cases": "DISPUTE_OR_ENFORCEMENT_REVIEW",
    "validators": "VALIDATOR_AUTHORITY_REVIEW",
    "validator_registry": "VALIDATOR_AUTHORITY_REVIEW",
    "validator_set": "VALIDATOR_AUTHORITY_REVIEW",
    "bft": "VALIDATOR_OR_CONSENSUS_REVIEW",
    "quarantine": "VALIDATOR_OR_CONSENSUS_REVIEW",
    "groups": "GROUP_MEMBERSHIP_OR_SCOPE_REVIEW",
    "group_memberships": "GROUP_MEMBERSHIP_OR_SCOPE_REVIEW",
    "system_queue": "SYSTEM_SCHEDULING_REVIEW",
}


def classify_authority_write_candidates(
    *,
    path: str,
    function: str,
    depth: int,
    direct_writes: list[str] | set[str],
    alias_writes: list[str] | set[str],
) -> dict[str, list[dict[str, Any]]]:
    """Classification only; a source-path name is never a semantic verdict."""
    sensitive = []
    unclassified = []
    ambiguous = []
    for kind, values in (
        ("DIRECT_STATE_ROOT", direct_writes),
        ("MUTABLE_ALIAS_ROOT", alias_writes),
    ):
        for state_root in sorted(set(values)):
            item = {
                "source_path": path,
                "source_function": function,
                "import_depth": depth,
                "write_signal": kind,
                "state_root": state_root,
                "authority_area": AUTHORITY_REVIEW_ROOTS.get(state_root),
                "status": "UNVERIFIED_STATIC_WRITE_CANDIDATE",
            }
            if state_root.startswith("<") or not state_root:
                ambiguous.append(item)
            elif item["authority_area"]:
                sensitive.append(item)
            else:
                unclassified.append(item)
    return {
        "authority_sensitive_write_candidates": sensitive,
        "unclassified_state_write_candidates": unclassified,
        "ambiguous_state_write_candidates": ambiguous,
    }


def trace_effect_candidates(
    repo: Path, rows: dict[str, dict], *, require_commit_pin: bool = False
) -> dict[str, Any]:
    """Bounded static candidates. Strict pin proves scanned file identity only."""
    starting_commit = repo_commit(repo)
    source_cache: dict[str, tuple[dict[str, ast.AST], dict[str, str]]] = {}

    def source(path: str) -> tuple[dict[str, ast.AST], dict[str, str]]:
        relative = Path(path)
        if (
            relative.is_absolute()
            or ".." in relative.parts
            or not path.startswith(str(RUNTIME / ""))
            or relative.suffix != ".py"
        ):
            raise ContractError("unsafe_effect_source:" + path)
        if path not in source_cache:
            filename = repo / relative
            if not filename.is_file():
                raise ContractError("missing_effect_source:" + path)
            tree = ast.parse(filename.read_text(encoding="utf-8"), filename=path)
            functions = {
                n.name: n
                for n in tree.body
                if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
            }
            imports: dict[str, str] = {}
            for n in tree.body:
                if isinstance(n, ast.ImportFrom):
                    if n.level:
                        # The current file is a module, not a package. Resolve
                        # relative imports against its containing Python package.
                        module = (
                            path.removeprefix(str(PREFIX / "src") + "/")
                            .removesuffix(".py")
                            .replace("/", ".")
                        )
                        package = module.split(".")[:-1]
                        if n.level > len(package):
                            continue
                        parent = package[: len(package) - n.level + 1]
                        prefix = ".".join(parent + (n.module.split(".") if n.module else []))
                    else:
                        prefix = n.module or ""
                    if prefix:
                        for alias in n.names:
                            imports[alias.asname or alias.name] = prefix + "." + alias.name
                elif isinstance(n, ast.Import):
                    for alias in n.names:
                        imports[alias.asname or alias.name.split(".")[0]] = alias.name
            source_cache[path] = (functions, imports)
        return source_cache[path]

    class Probe(ast.NodeVisitor):
        def __init__(
            self,
            functions: dict[str, ast.AST],
            imports: dict[str, str],
            root_variable: str = "state",
        ):
            self.functions = functions
            self.imports = imports
            self.root_variable = root_variable
            self.aliases: dict[str, str] = {}
            self.alias_roots: set[str] = set()
            self.imported_calls: list[dict[str, Any]] = []
            self.reads: set[str] = set()
            self.writes: set[str] = set()
            self.local_calls: set[str] = set()
            self.external: set[str] = set()
            self.authority: set[str] = set()
            self.alias_writes = 0
            self.unresolved_calls = 0

        def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
            # Nested scopes are not automatically executed by their enclosing function.
            return

        def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
            return

        @staticmethod
        def key(node: ast.AST) -> str:
            if isinstance(node, ast.Constant) and isinstance(node.value, str):
                return node.value
            return "<dynamic-key>"

        def origin(self, value: ast.AST) -> str | None:
            if isinstance(value, ast.Subscript):
                if isinstance(value.value, ast.Name) and value.value.id == self.root_variable:
                    return self.key(value.slice)
            if isinstance(value, ast.Call) and isinstance(value.func, ast.Attribute):
                target = value.func.value
                if (
                    isinstance(target, ast.Name)
                    and target.id == self.root_variable
                    and value.func.attr in {"get", "setdefault"}
                ):
                    return self.key(value.args[0]) if value.args else "<dynamic-key>"
            if isinstance(value, ast.Name):
                return self.aliases.get(value.id)
            return None

        def visit_Assign(self, node: ast.Assign) -> None:
            self.visit(node.value)
            origin = self.origin(node.value)
            for target in node.targets:
                if isinstance(target, ast.Name):
                    if origin is None:
                        self.aliases.pop(target.id, None)
                    else:
                        self.aliases[target.id] = origin
                self.visit(target)

        def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
            if node.value is not None:
                self.visit(node.value)
            if isinstance(node.target, ast.Name):
                origin = self.origin(node.value) if node.value else None
                if origin is None:
                    self.aliases.pop(node.target.id, None)
                else:
                    self.aliases[node.target.id] = origin
            self.visit(node.target)

        def visit_Subscript(self, node: ast.Subscript) -> None:
            if isinstance(node.value, ast.Name) and node.value.id == self.root_variable:
                key = self.key(node.slice)
                if isinstance(node.ctx, (ast.Store, ast.Del)):
                    self.writes.add(key)
                else:
                    self.reads.add(key)
            elif isinstance(node.ctx, (ast.Store, ast.Del)):
                # A local variable may point into a root map; aliases are
                # MAY-link candidates, never proven mutation paths.
                self.alias_writes += 1
                if isinstance(node.value, ast.Name) and node.value.id in self.aliases:
                    self.alias_roots.add(self.aliases[node.value.id])
            self.generic_visit(node)

        def visit_Call(self, node: ast.Call) -> None:
            call = node.func
            name = ""
            if isinstance(call, ast.Name):
                name = call.id
                if name in self.functions:
                    self.local_calls.add(name)
                elif name in self.imports:
                    self.external.add(self.imports[name])
                    self.imported_calls.append(
                        {
                            "target": self.imports[name],
                            "line": node.lineno,
                            "state_positional_indices": [
                                i
                                for i, arg in enumerate(node.args)
                                if isinstance(arg, ast.Name) and arg.id == self.root_variable
                            ],
                            "state_keywords": [
                                kw.arg
                                for kw in node.keywords
                                if kw.arg
                                and isinstance(kw.value, ast.Name)
                                and kw.value.id == self.root_variable
                            ],
                        }
                    )
                else:
                    self.unresolved_calls += 1
            elif isinstance(call, ast.Attribute):
                name = call.attr
                if isinstance(call.value, ast.Name):
                    owner = call.value.id
                    if owner == self.root_variable:
                        if name in {"get", "setdefault", "pop"}:
                            key = self.key(node.args[0]) if node.args else "<dynamic-key>"
                            if name != "setdefault":
                                self.reads.add(key)
                            if name != "get":
                                self.writes.add(key)
                        elif name in {"update", "clear", "popitem"}:
                            self.writes.add("<unknown-root-keys>")
                    elif owner in self.aliases and name in {
                        "setdefault",
                        "pop",
                        "popitem",
                        "update",
                        "clear",
                        "append",
                        "extend",
                        "insert",
                        "remove",
                        "discard",
                        "add",
                    }:
                        self.alias_writes += 1
                        self.alias_roots.add(self.aliases[owner])
                    elif owner in self.imports:
                        self.external.add(self.imports[owner] + "." + name)
                        self.imported_calls.append(
                            {
                                "target": self.imports[owner] + "." + name,
                                "line": node.lineno,
                                "state_positional_indices": [
                                    i
                                    for i, arg in enumerate(node.args)
                                    if isinstance(arg, ast.Name) and arg.id == self.root_variable
                                ],
                                "state_keywords": [
                                    kw.arg
                                    for kw in node.keywords
                                    if kw.arg
                                    and isinstance(kw.value, ast.Name)
                                    and kw.value.id == self.root_variable
                                ],
                            }
                        )
                    else:
                        self.unresolved_calls += 1
                else:
                    self.unresolved_calls += 1
            else:
                self.unresolved_calls += 1
            if re.search(
                r"(?i)(?:authoriz|sanction|enforc|ban|lock|juror|reviewer|"
                r"reput|quorum|poh|role|vote|ballot|eligib|permission|"
                r"validator|penalt|appeal|recovery|disput)",
                name,
            ):
                self.authority.add(name)
            self.generic_visit(node)

    transactions = []
    for tx_type, row in sorted(rows.items()):
        path = row["source_path"]
        functions, imports = source(path)
        root = row.get("routed_function") or row["entrypoint"]
        found = root in functions
        seen: set[str] = set()
        queue = [(root, 0)]
        reads: set[str] = set()
        writes: set[str] = set()
        external: set[str] = set()
        authority: set[str] = set()
        alias_writes = 0
        alias_roots: set[str] = set()
        imported_call_sites: list[dict[str, Any]] = []
        unresolved_calls = 0
        truncated = False
        while queue:
            current, depth = queue.pop(0)
            if current in seen:
                continue
            if len(seen) >= 32 or depth > 2:
                truncated = True
                continue
            fn = functions.get(current)
            if fn is None:
                continue
            seen.add(current)
            probe = Probe(functions, imports)
            for statement in fn.body:
                probe.visit(statement)
            reads.update(probe.reads)
            writes.update(probe.writes)
            external.update(probe.external)
            authority.update(probe.authority)
            alias_writes += probe.alias_writes
            alias_roots.update(probe.alias_roots)
            unresolved_calls += probe.unresolved_calls
            for call in probe.imported_calls:
                imported_call_sites.append(
                    {"caller_function": current, "caller_source_path": path, **call}
                )
            for callee in sorted(probe.local_calls):
                if callee not in seen:
                    queue.append((callee, depth + 1))
        # Follow only explicit direct state handoffs into a resolved
        # top-level imported function. A missing/dynamic/third-party callee
        # stays unresolved; never execute imported code or assume causality.
        imported_details: list[dict[str, Any]] = []
        for call in sorted(
            imported_call_sites,
            key=lambda c: (c["caller_function"], c["line"], c["target"]),
        ):
            target = call["target"]
            status = "IMPORT_TARGET_UNRESOLVED"
            target_path = None
            target_function = None
            root_arg = None
            imported_reads: set[str] = set()
            imported_writes: set[str] = set()
            imported_alias_roots: set[str] = set()
            if target.startswith("weall.runtime.") and "." in target:
                module, target_function = target.rsplit(".", 1)
                target_path = str(module_path(module))
                filename = repo / target_path
                if filename.is_file():
                    target_functions, target_imports = source(target_path)
                    imported_fn = target_functions.get(target_function)
                    if imported_fn:
                        positional = imported_fn.args.posonlyargs + imported_fn.args.args
                        if call["state_positional_indices"]:
                            index = call["state_positional_indices"][0]
                            if index < len(positional):
                                root_arg = positional[index].arg
                        elif call["state_keywords"]:
                            keyword = call["state_keywords"][0]
                            if keyword in {
                                arg.arg for arg in positional + imported_fn.args.kwonlyargs
                            }:
                                root_arg = keyword
                        if root_arg:
                            probe = Probe(
                                target_functions,
                                target_imports,
                                root_variable=root_arg,
                            )
                            for statement in imported_fn.body:
                                probe.visit(statement)
                            imported_reads.update(probe.reads)
                            imported_writes.update(probe.writes)
                            imported_alias_roots.update(probe.alias_roots)
                            status = "EXPLICIT_STATE_HANDOFF_IMPORTED_FUNCTION_CANDIDATE"
                        else:
                            status = "IMPORTED_FUNCTION_FOUND_STATE_HANDOFF_UNPROVEN"
                    else:
                        status = "IMPORT_TARGET_NOT_TOP_LEVEL_FUNCTION"
                else:
                    status = "IMPORTED_SOURCE_ABSENT_OR_DYNAMIC"
            imported_details.append(
                {
                    "caller_function": call["caller_function"],
                    "caller_source_path": call["caller_source_path"],
                    "line": call["line"],
                    "target": target,
                    "target_source_path": target_path,
                    "target_function": target_function,
                    "state_parameter": root_arg,
                    "status": status,
                    "state_root_read_candidates": sorted(imported_reads),
                    "state_root_write_candidates": sorted(imported_writes),
                    "alias_root_write_candidates": sorted(imported_alias_roots),
                    "verification": "UNREVIEWED_ONE_HOP_STATIC_OBSERVATION",
                }
            )
        # Follow at most one additional imported call edge (depth two).
        # No dynamic dispatch, callbacks, transitive closure, or causal proof.
        transitive_details: list[dict[str, Any]] = []
        transitive_truncated = False
        for parent in imported_details:
            if parent["status"] != "EXPLICIT_STATE_HANDOFF_IMPORTED_FUNCTION_CANDIDATE":
                continue
            parent_path = parent["target_source_path"]
            parent_fn = parent["target_function"]
            parent_functions, parent_imports = source(parent_path)
            parent_probe = Probe(
                parent_functions, parent_imports, root_variable=parent["state_parameter"]
            )
            for statement in parent_functions[parent_fn].body:
                parent_probe.visit(statement)
            for child in sorted(
                parent_probe.imported_calls, key=lambda x: (x["line"], x["target"])
            ):
                if len(transitive_details) >= 32:
                    transitive_truncated = True
                    break
                target = child["target"]
                detail: dict[str, Any] = {
                    "parent_target": parent["target"],
                    "parent_source_path": parent_path,
                    "line": child["line"],
                    "target": target,
                    "target_source_path": None,
                    "target_function": None,
                    "state_parameter": None,
                    "depth": 2,
                    "status": "TRANSITIVE_IMPORT_UNRESOLVED",
                    "state_root_read_candidates": [],
                    "state_root_write_candidates": [],
                    "alias_root_write_candidates": [],
                    "verification": "UNREVIEWED_BOUNDED_TRANSITIVE_SOURCE_CANDIDATE",
                }
                if target == parent["target"]:
                    detail["status"] = "TRANSITIVE_IMPORT_CYCLE_UNRESOLVED"
                elif target.startswith("weall.runtime.") and "." in target:
                    module, fn_name = target.rsplit(".", 1)
                    target_path = str(module_path(module))
                    detail["target_source_path"] = target_path
                    detail["target_function"] = fn_name
                    if (repo / target_path).is_file():
                        fn_map, fn_imports = source(target_path)
                        node = fn_map.get(fn_name)
                        if node is None:
                            detail["status"] = "TRANSITIVE_FUNCTION_NOT_TOP_LEVEL"
                        else:
                            positional = node.args.posonlyargs + node.args.args
                            state_parameter = None
                            if child["state_positional_indices"]:
                                index = child["state_positional_indices"][0]
                                if index < len(positional):
                                    state_parameter = positional[index].arg
                            elif child["state_keywords"]:
                                keyword = child["state_keywords"][0]
                                if keyword in {a.arg for a in positional + node.args.kwonlyargs}:
                                    state_parameter = keyword
                            if state_parameter:
                                probe = Probe(fn_map, fn_imports, root_variable=state_parameter)
                                for statement in node.body:
                                    probe.visit(statement)
                                detail["state_parameter"] = state_parameter
                                detail["state_root_read_candidates"] = sorted(probe.reads)
                                detail["state_root_write_candidates"] = sorted(probe.writes)
                                detail["alias_root_write_candidates"] = sorted(probe.alias_roots)
                                detail["status"] = "TRANSITIVE_EXPLICIT_STATE_HANDOFF_CANDIDATE"
                            else:
                                detail["status"] = "TRANSITIVE_STATE_HANDOFF_UNPROVEN"
                    else:
                        detail["status"] = "TRANSITIVE_SOURCE_ABSENT"
                transitive_details.append(detail)
            if transitive_truncated:
                break
        classified_sources = [
            classify_authority_write_candidates(
                path=path,
                function=root,
                depth=0,
                direct_writes=writes,
                alias_writes=alias_roots,
            )
        ]
        for item in imported_details:
            if item["status"] == "EXPLICIT_STATE_HANDOFF_IMPORTED_FUNCTION_CANDIDATE":
                classified_sources.append(
                    classify_authority_write_candidates(
                        path=item["target_source_path"],
                        function=item["target_function"],
                        depth=1,
                        direct_writes=item["state_root_write_candidates"],
                        alias_writes=item["alias_root_write_candidates"],
                    )
                )
        for item in transitive_details:
            if item["status"] == "TRANSITIVE_EXPLICIT_STATE_HANDOFF_CANDIDATE":
                classified_sources.append(
                    classify_authority_write_candidates(
                        path=item["target_source_path"],
                        function=item["target_function"],
                        depth=2,
                        direct_writes=item["state_root_write_candidates"],
                        alias_writes=item["alias_root_write_candidates"],
                    )
                )
        classified = {
            field: sorted(
                [effect for source in classified_sources for effect in source[field]],
                key=lambda item: (
                    item["source_path"],
                    item["source_function"],
                    item["import_depth"],
                    item["state_root"],
                    item["write_signal"],
                ),
            )
            for field in (
                "authority_sensitive_write_candidates",
                "unclassified_state_write_candidates",
                "ambiguous_state_write_candidates",
            )
        }
        transactions.append(
            {
                "tx_type": tx_type,
                "source_path": path,
                "entrypoint": row["entrypoint"],
                "anchor_function": root,
                "anchor_status": (
                    "DIRECT_ROUTE_ANCHOR_UNVERIFIED"
                    if row.get("routed_function") and found
                    else "SHARED_ENTRYPOINT_AMBIGUOUS"
                    if found
                    else "FUNCTION_ANCHOR_UNRESOLVED"
                ),
                "local_functions_visited": sorted(seen),
                "direct_state_root_read_candidates": sorted(reads),
                "direct_state_root_write_candidates": sorted(writes),
                "imported_call_candidates": sorted(external)[:80],
                "authority_name_signals": sorted(authority)[:80],
                "unresolved_call_count": unresolved_calls,
                "potential_alias_write_sites": alias_writes,
                "state_alias_root_write_candidates": sorted(alias_roots),
                "imported_function_candidates": imported_details,
                "transitive_imported_function_candidates": transitive_details,
                "transitive_imported_candidate_count": len(transitive_details),
                "transitive_import_truncated": transitive_truncated,
                **classified,
                "authority_review_status": "UNADJUDICATED_REVIEW_REQUIRED",
                "imported_function_candidate_count": len(imported_details),
                "imported_state_handoff_candidate_count": sum(
                    x["status"] == "EXPLICIT_STATE_HANDOFF_IMPORTED_FUNCTION_CANDIDATE"
                    for x in imported_details
                ),
                "trace_truncated_or_unresolved": truncated or transitive_truncated or not found,
                "verification": "STATIC_PARTIAL_NOT_SEMANTICALLY_VERIFIED",
            }
        )

    scheduler_path = str(RUNTIME / "scheduler_pipeline.py")
    scheduler_rows = []
    if (repo / scheduler_path).is_file():
        scheduler_functions, _ = source(scheduler_path)
        for name, fn in sorted(scheduler_functions.items()):
            if name.startswith(("run_", "emit_", "prune_")):
                calls = []
                for node in ast.walk(fn):
                    if isinstance(node, ast.Call):
                        if isinstance(node.func, ast.Name):
                            calls.append({"line": node.lineno, "target": node.func.id})
                        elif isinstance(node.func, ast.Attribute):
                            owner = node.func.value
                            if isinstance(owner, ast.Name):
                                calls.append(
                                    {"line": node.lineno, "target": owner.id + "." + node.func.attr}
                                )
                scheduler_rows.append(
                    {
                        "function": name,
                        "source_path": scheduler_path,
                        "static_call_sites": sorted(
                            calls, key=lambda call: (call["line"], call["target"])
                        ),
                    }
                )
        scheduler_status = "STATIC_INVENTORY_NOT_EXECUTION_PROOF"
    else:
        scheduler_status = "SCHEDULER_SOURCE_ABSENT_UNRESOLVED"
    # Pin only the finite set of source files this scanner actually parsed.
    scanned_paths = sorted(source_cache)
    if repo_commit(repo) != starting_commit:
        raise ContractError("effect_source_commit_changed_during_scan")
    source_files = [{"path": path, "sha256": digest(repo / path)} for path in scanned_paths]
    pin_status = "UNVERIFIED_WORKTREE"
    if require_commit_pin:
        tracked = subprocess.run(
            ["git", "-C", str(repo), "ls-files", "-z", "--", *scanned_paths],
            capture_output=True,
            check=False,
        )
        if tracked.returncode:
            raise ContractError("effect_source_tracking_check_failed")
        tracked_paths = {p.decode("utf-8") for p in tracked.stdout.split(b"\0") if p}
        if tracked_paths != set(scanned_paths):
            raise ContractError("effect_source_untracked_path")
        status = subprocess.run(
            [
                "git",
                "-C",
                str(repo),
                "status",
                "--porcelain",
                "--untracked-files=all",
                "-z",
                "--",
                *scanned_paths,
            ],
            capture_output=True,
            check=False,
        )
        if status.returncode or status.stdout:
            raise ContractError("effect_source_dirty_or_unverifiable")
        if repo_commit(repo) != starting_commit:
            raise ContractError("effect_source_commit_changed_during_pin")
        pin_status = "SCANNED_FILES_TRACKED_AND_CLEAN_AT_HEAD"
    return {
        "schema": "weall.change-gate.static-effect-candidates.v0.6",
        "source_commit": starting_commit,
        "source_pin": {
            "status": pin_status,
            "scanned_file_count": len(source_files),
            "scanned_files": source_files,
            "scope_note": "Only scanned files; not every runtime or repository file",
        },
        "transaction_count": len(transactions),
        "transactions_with_authority_write_candidates": sum(
            bool(tx["authority_sensitive_write_candidates"]) for tx in transactions
        ),
        "authority_sensitive_write_candidate_count": sum(
            len(tx["authority_sensitive_write_candidates"]) for tx in transactions
        ),
        "authority_review_taxonomy_status": "NON_NORMATIVE_EXACT_KEY_REVIEW_SIGNALS",
        "transactions": transactions,
        "scheduler_inventory": scheduler_rows,
        "scheduler_status": scheduler_status,
        "invariants": {
            "runtime_authorization_verified": False,
            "state_alias_effects_verified": False,
            "scheduler_transaction_causality_verified": False,
            "consensus_replay_verified": False,
        },
        "release_verdict": "BLOCKED_PENDING_SEMANTIC_TRACING_AND_INDEPENDENT_REVIEW",
    }


def load_policy() -> dict[str, Any]:
    d = read_json(POLICY_ROOT / "requirements.json")
    if d.get("policy_version") != "0.1.0":
        raise ContractError("unknown_policy_version")
    seen = set()
    for x in d["requirements"]:
        if x["id"] in seen:
            raise ContractError("duplicate_requirement:" + x["id"])
        seen.add(x["id"])
    return d


def domain_requirements(domains: set[str], policy: dict[str, Any]) -> list[dict[str, Any]]:
    selected = []
    for req in policy["requirements"]:
        scope = set(req.get("domains", []))
        if "*" in scope or scope & domains:
            selected.append(req)
    return sorted(selected, key=lambda r: r["id"])


def impacted_paths(
    repo: Path, rows: dict[str, dict], paths: list[str], policy: dict[str, Any]
) -> dict[str, Any]:
    all_types = set(rows)
    path_to_types: dict[str, set[str]] = defaultdict(set)
    for name, row in rows.items():
        path_to_types[row["source_path"]].add(name)
    impact_types: set[str] = set()
    unmapped: list[str] = []
    per_path = []
    high_risk = {str(RUNTIME / f) for f in policy["all_type_runtime_paths"]}
    special_names = {
        str(INDEX),
        str(RUNTIME / "tx_schema.py"),
        str(RUNTIME / "tx_contracts.py"),
        str(RUNTIME / "domain_dispatch.py"),
    }
    for p in sorted(set(paths)):
        raw = p.replace("\\", "/")
        raw_path = Path(raw)
        # Strictly reject paths escaped from the repository root, even when
        # normalized spelling could conceal a leading slash or `..`.
        if raw_path.is_absolute() or ".." in raw_path.parts:
            unmapped.append(p)
            continue
        normalized = raw.removeprefix("./")
        if not normalized or normalized == ".":
            unmapped.append(p)
            continue
        triggered: set[str] = set()
        reason = ""
        if normalized in special_names or normalized in high_risk:
            triggered = all_types.copy()
            reason = "consensus_or_contract_shared_surface"
        elif normalized in path_to_types:
            triggered = path_to_types[normalized]
            reason = "canonical_authoritative_handler"
        elif normalized.startswith(str(RUNTIME) + "/"):
            triggered = all_types.copy()
            reason = "unmapped_shared_runtime_fail_conservatively"
        elif normalized.startswith(str(PREFIX / "specs") + "/") or normalized.startswith("specs/"):
            triggered = all_types.copy()
            reason = "normative_source_change"
        elif (
            normalized.startswith(str(PREFIX / "generated") + "/")
            or normalized.startswith(str(PREFIX / "scripts") + "/")
            or normalized.startswith("web/src/generated/")
        ):
            # Generated protocol views, compilers and status surfaces must be
            # reviewed with the authoritative source and derivation workflow.
            triggered = all_types.copy()
            reason = "generated_contract_or_compiler_surface_conservative"
        elif normalized.startswith("governance/traceability/") or "change_gate" in normalized:
            triggered = all_types.copy()
            reason = "self_modifying_change_control"
        elif normalized.endswith(".py") and normalized.startswith(str(PREFIX / "src/weall/")):
            triggered = all_types.copy()
            reason = "unmapped_backend_fail_conservatively"
        elif normalized.startswith("web/") or normalized.startswith(str(PREFIX / "tests/")):
            # Even changes confined to UI/tests can alter the apparent rights or evidence.
            candidate = repo / normalized
            if candidate.is_file() and candidate.stat().st_size <= 1_000_000:
                content = candidate.read_text(encoding="utf-8", errors="replace")
                triggered = {n for n in rows if re.search(r"\b" + re.escape(n) + r"\b", content)}
            if not triggered:
                # Never assume a frontend surface has no authority implications.
                triggered = all_types.copy()
                reason = "unresolved_frontend_or_test_surface_conservative"
            else:
                reason = "symbol_reference_candidate_not_proven_dependency"
        elif normalized.startswith(".github/"):
            triggered = all_types.copy()
            reason = "release_gate_or_ci_change"
        else:
            unmapped.append(normalized)
            reason = "no_verified_authority_mapping"
        impact_types.update(triggered)
        per_path.append({"path": normalized, "reason": reason, "tx_types": sorted(triggered)})
    direct_domains = {str(rows[t]["domain"]) for t in impact_types}
    cross = policy["cross_domain_effects"]
    domains = set(direct_domains)
    for domain in direct_domains:
        domains.update(cross.get(domain, []))
    requirements = domain_requirements(domains, policy)
    return {
        "policy_version": policy["policy_version"],
        "changed_paths": per_path,
        "unmapped_paths": sorted(set(unmapped)),
        "tx_types": sorted(impact_types),
        "direct_domains": sorted(direct_domains),
        "affected_domains": sorted(domains),
        "requirements": [
            {
                "id": r["id"],
                "title": r["title"],
                "source_ref": r["source_ref"],
                "status_category": r["status_category"],
                "required_evidence": r["required_evidence"],
            }
            for r in requirements
        ],
        "release_verdict": "BLOCKED_PENDING_EVIDENCE",
    }


def git_paths(repo: Path, base: str, head: str) -> list[str]:
    # No shell, Git process is read-only. The 3-dot form includes merge base.
    proc = subprocess.run(
        [
            "git",
            "-C",
            str(repo),
            "diff",
            "--name-only",
            "--diff-filter=ACDMRT",
            "-z",
            f"{base}...{head}",
            "--",
        ],
        capture_output=True,
        check=False,
    )
    if proc.returncode:
        raise ContractError("git_diff_failed:" + proc.stderr.decode(errors="replace")[:350])
    return [p.decode("utf-8", errors="replace") for p in proc.stdout.split(b"\0") if p]


def repo_commit(repo: Path) -> str:
    proc = subprocess.run(
        ["git", "-C", str(repo), "rev-parse", "HEAD"], capture_output=True, text=True
    )
    if proc.returncode or not SHA_RE.fullmatch(proc.stdout.strip()):
        raise ContractError("repo_commit_unavailable")
    return proc.stdout.strip()


def evaluate_evidence(
    impact: dict, evidence_path: Path | None, commit: str, owner: str | None
) -> dict[str, Any]:
    required = {r["id"]: set(r["required_evidence"]) for r in impact["requirements"]}
    accepted: dict[str, set[str]] = defaultdict(set)
    invalid = []
    if evidence_path:
        e = read_json(evidence_path)
        if not isinstance(e, dict) or not isinstance(e.get("claims"), list):
            raise ContractError("malformed_evidence_manifest")
        for claim in e["claims"]:
            rid = claim.get("requirement_id")
            ec = claim.get("evidence_class")
            if rid not in required or ec not in required[rid]:
                invalid.append(
                    {
                        "requirement_id": rid,
                        "evidence_class": ec,
                        "reason": "unrequested_requirement_or_class",
                    }
                )
                continue
            if claim.get("commit_sha") != commit or not SHA_RE.fullmatch(
                str(claim.get("commit_sha", ""))
            ):
                invalid.append(
                    {"requirement_id": rid, "evidence_class": ec, "reason": "unpinned_commit"}
                )
                continue
            if claim.get("result") != "PASS" or claim.get("exit_code") != 0:
                invalid.append(
                    {"requirement_id": rid, "evidence_class": ec, "reason": "not_passing"}
                )
                continue
            reviewer = str(claim.get("independent_reviewer") or "").strip()
            if not reviewer or (owner and reviewer == owner):
                invalid.append(
                    {
                        "requirement_id": rid,
                        "evidence_class": ec,
                        "reason": "independent_review_absent",
                    }
                )
                continue
            if not all(
                claim.get(f)
                for f in ("test_id", "command", "timestamp_utc", "run_id", "log_path", "log_sha256")
            ):
                invalid.append(
                    {
                        "requirement_id": rid,
                        "evidence_class": ec,
                        "reason": "missing_evidence_fields",
                    }
                )
                continue
            root = evidence_path.parent.resolve()
            path = (root / str(claim["log_path"])).resolve()
            if (
                not path.is_relative_to(root)
                or not path.is_file()
                or not re.fullmatch(r"[0-9a-f]{64}", str(claim["log_sha256"]))
                or digest(path) != claim["log_sha256"]
            ):
                invalid.append(
                    {
                        "requirement_id": rid,
                        "evidence_class": ec,
                        "reason": "log_missing_or_digest_mismatch_or_unsafe_path",
                    }
                )
                continue
            accepted[rid].add(ec)
    missing = {
        rid: sorted(classes - accepted[rid])
        for rid, classes in required.items()
        if classes - accepted[rid]
    }
    # This validates manifest completeness + file digests, NOT test semantics,
    # reviewer identity, true independence or constitutional authorization.
    ready = not (missing or invalid or impact["unmapped_paths"] or not impact["tx_types"])
    return {
        "evidence_claims_format_valid": not invalid,
        "evidence_claims_present": bool(evidence_path),
        "evidence_not_cryptographically_attested": True,
        "validated_classes": {k: sorted(v) for k, v in sorted(accepted.items())},
        "missing_requirement_evidence": missing,
        "invalid_claims": invalid,
        "gate_decision": "MANIFEST_COMPLETE_REQUIRES_INDEPENDENT_AUDIT" if ready else "BLOCKED",
    }


def clean_contract_checkout(repo: Path, rows: dict[str, dict]) -> bool:
    paths = sorted(
        {str(INDEX), str(RUNTIME / "tx_contracts.py"), str(RUNTIME / "tx_schema.py")}
        | {r["source_path"] for r in rows.values()}
    )
    p = subprocess.run(
        ["git", "-C", str(repo), "diff", "--quiet", "HEAD", "--", *paths], capture_output=True
    )
    return p.returncode == 0


def report_md(impact: dict) -> str:
    out = [
        "# WeAll code-change → TX/domain/requirements impact",
        "",
        f"**Release decision:** {impact['release_verdict']}",
        "",
        "**Important:** This is conservative source-path/symbol impact inference, not proof of a semantic dependency or constitutional compliance.",
        "",
        f"- Changed files: {len(impact['changed_paths'])}",
        f"- Canonical TX types impacted: {len(impact['tx_types'])}",
        f"- Affected domains (including cross-domain policy): {', '.join(impact['affected_domains']) or 'NONE'}",
        "",
        "## Changed path classification",
        "",
        "| Path | Conservative mapping | TX types |",
        "| --- | --- | ---: |",
    ]
    for item in impact["changed_paths"]:
        out.append(f"| `{item['path']}` | {item['reason']} | {len(item['tx_types'])} |")
    if impact["unmapped_paths"]:
        out += ["", "**Unmapped changes (fail-closed):** " + ", ".join(impact["unmapped_paths"])]
    out += [
        "",
        "## Triggered requirements",
        "",
        "| ID | Requirement | Source | Status | Required evidence classes |",
        "| --- | --- | --- | --- | --- |",
    ]
    for r in impact["requirements"]:
        out.append(
            f"| {r['id']} | {r['title']} | {r['source_ref']} | {r['status_category']} | {', '.join(r['required_evidence'])} |"
        )
    out += [
        "",
        "## Canonical TX types",
        "",
        ", ".join(f"`{t}`" for t in impact["tx_types"]),
        "",
        "## Limits",
        "",
        "- Neither CI availability nor passing existing tests closes a triggered requirement automatically.",
        "- Source-path scope is deliberately coarse; transitive semantic effects may require additional manual review.",
        "- Runtime authorization must independently enforce constitutional rules.",
        "- This gate never updates ledger state, replays consensus, or evaluates deployment-level liveness.",
        "",
    ]
    return "\n".join(out)


def matrix_md(rows: dict[str, dict], policy: dict[str, Any]) -> str:
    out = [
        "# WeAll canonical transaction → implementation → authority matrix",
        "",
        f"Coverage: **{len(rows)} canonical transaction names**. The canonical ID, repository position, model, and applier are extracted, not guessed.",
        "Unknown fields remain null/NOT_VERIFIED until reviewed; this is NOT a complete ACC-003 contract matrix.",
        "",
        "| Domain | Canonical TX | ID | Model | Code handler | Authority policy |",
        "| --- | --- | --- | --- | --- | --- |",
    ]
    for r in sorted(rows.values(), key=lambda x: (x["domain"], x["tx_type"])):
        out.append(
            "| "
            + " | ".join(
                [
                    r["domain"],
                    "`" + r["tx_type"] + "`",
                    "`" + r["canonical_id"] + "`",
                    r["payload_model"],
                    "`" + (r["routed_function"] or r["entrypoint"]) + "`",
                    r["authority_policy_status"],
                ]
            )
            + " |"
        )
    out += [
        "",
        "## Domain → constitutional / specification requirements",
        "",
        "These are conservative impact triggers, not proof of a valid authorization contract.",
        "",
        "| Domain | Triggered requirement IDs |",
        "| --- | --- |",
    ]
    domains = sorted({r["domain"] for r in rows.values()})
    for d in domains:
        aff = {d} | set(policy["cross_domain_effects"].get(d, []))
        reqs = domain_requirements(aff, policy)
        out.append(f"| {d} | {', '.join(x['id'] for x in reqs)} |")
    return "\n".join(out) + "\n"


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("command", choices=["build", "impact", "gate"])
    p.add_argument(
        "--v2-effect-links",
        action="store_true",
        help="Include candidate-only v2 requirement links; not an approval gate",
    )
    p.add_argument(
        "--repo", type=Path, required=True, help="Git repository root containing Weall-Protocol/"
    )
    p.add_argument(
        "--out", type=Path, required=True, help="External output directory; never the repository"
    )
    p.add_argument(
        "--changed", nargs="*", default=None, help="File paths relative to repository root"
    )
    p.add_argument("--base", help="Git diff base ref (alternative to --changed)")
    p.add_argument("--head", help="Git diff head ref")
    p.add_argument(
        "--evidence", type=Path, help="Review + test evidence claims manifest, gate only"
    )
    p.add_argument("--owner", help="Declared developer identity, gate only")
    p.add_argument(
        "--authority-review-submissions",
        type=Path,
        help="External self-reported review claims; never treated as approved",
    )
    args = p.parse_args(argv)
    repo = args.repo.resolve()
    out = args.out.resolve()
    if not (repo / INDEX).is_file():
        raise ContractError("not_a_weall_repo_or_index_missing:" + str(repo))
    if out == repo or repo in out.parents:
        raise ContractError("output_must_be_outside_repository")
    if args.authority_review_submissions and not args.v2_effect_links:
        raise ContractError("authority_review_submissions_require_v2_effect_links")
    rows = extract_routes(repo)
    policy = load_policy()
    existing_v2 = {}
    for key, relative in (
        ("tx_contract_matrix", "generated/v2/tx_contract_matrix.json"),
        ("requirement_traceability", "generated/v2/requirement_traceability.json"),
    ):
        v2_path = repo / PREFIX / relative
        existing_v2[key] = {
            "path": str(PREFIX / relative),
            "present": v2_path.is_file(),
            "sha256": digest(v2_path) if v2_path.is_file() else None,
            "schema_reconciliation_status": "PENDING_NOT_VERIFIED",
        }
    snapshot = {
        "schema": "weall.derived.tx-contract-matrix.v0.1",
        "policy_version": policy["policy_version"],
        "existing_v2_derivatives": existing_v2,
        "source_commit": repo_commit(repo),
        "tx_index_sha256": digest(repo / INDEX),
        "source_pdf_sha256": policy["normative_source"]["sha256"],
        "normative_source_authorization": policy["normative_source"]["status"],
        "transactions": [rows[n] for n in sorted(rows)],
    }
    atomic_write(out / "tx_implementation_matrix.json", canonical_bytes(snapshot))
    effects = trace_effect_candidates(repo, rows, require_commit_pin=args.v2_effect_links)
    atomic_write(out / "tx_effect_candidates.json", canonical_bytes(effects))
    if args.v2_effect_links:
        import reconcile_v2

        tx_source = repo / reconcile_v2.V2_TX
        req_source = repo / reconcile_v2.V2_REQUIREMENTS
        if not tx_source.is_file() or not req_source.is_file():
            raise ContractError("v2_effect_link_inputs_missing")
        reconciled = reconcile_v2.reconcile(
            read_json(repo / INDEX),
            rows,
            read_json(tx_source),
            read_json(req_source),
            [],
            checkout_commit=snapshot["source_commit"],
            effects=effects,
            require_effect_pin=True,
            review_submissions=(
                read_json(args.authority_review_submissions)
                if args.authority_review_submissions else None
            ),
        )
        reconcile_v2.write_results(reconciled, out)
    atomic_write(out / "tx_implementation_matrix.md", matrix_md(rows, policy).encode("utf-8"))
    with (out / "tx_implementation_matrix.csv").open("w", encoding="utf-8", newline="") as f:
        fields = [
            "tx_type",
            "canonical_id",
            "repository_position",
            "domain",
            "origin",
            "context",
            "payload_model",
            "handler",
            "source_path",
            "entrypoint",
            "routed_function",
            "route_status",
            "authority_policy_status",
            "verification_status",
            "existing_contract_map_status",
        ]
        w = csv.DictWriter(f, fieldnames=fields, extrasaction="ignore")
        w.writeheader()
        w.writerows(rows[n] for n in sorted(rows))
    print(f"Canonical mapping: {len(rows)} types; output {out}")
    if args.command == "build":
        return 0
    paths = (
        args.changed
        if args.changed is not None
        else git_paths(repo, args.base, args.head)
        if args.base and args.head
        else None
    )
    if paths is None:
        raise ContractError("impact_requires_changed_or_base_and_head")
    impact = impacted_paths(repo, rows, paths, policy)
    impact["source_commit"] = snapshot["source_commit"]
    impact["source_index_sha256"] = snapshot["tx_index_sha256"]
    atomic_write(out / "impact.json", canonical_bytes(impact))
    atomic_write(out / "impact.md", report_md(impact).encode("utf-8"))
    print(
        f"Impact: {len(impact['tx_types'])} tx types, {len(impact['requirements'])} requirements, unmapped={impact['unmapped_paths']}"
    )
    if args.command == "gate":
        if not clean_contract_checkout(repo, rows):
            raise ContractError("dirty_contract_code_not_bound_to_commit")
        if args.head:
            resolved = subprocess.run(
                ["git", "-C", str(repo), "rev-parse", args.head], capture_output=True, text=True
            )
            if resolved.returncode or resolved.stdout.strip() != snapshot["source_commit"]:
                raise ContractError("head_diff_does_not_match_checked_out_contract_commit")
        res = evaluate_evidence(impact, args.evidence, snapshot["source_commit"], args.owner)
        if (
            policy["policy_status"] != "GOVERNANCE_APPROVED"
            or policy["normative_source"]["status"] != "ACTIVE_AUTHORIZED"
            or any(
                r["authority_policy_status"] != "VERIFIED" or r["verification_status"] != "VERIFIED"
                for r in rows.values()
            )
        ):
            res["gate_decision"] = "BLOCKED_UNRATIFIED_POLICY_OR_UNVERIFIED_CONTRACTS"
            res["requires_constitutional_authorization"] = True
        # This candidate cannot produce an automated merge authorization.
        # Complete manifest evidence still requires separate independent review
        # and trusted-base CI verification not provided by this prototype.
        elif res["gate_decision"] == "MANIFEST_COMPLETE_REQUIRES_INDEPENDENT_AUDIT":
            res["gate_decision"] = "BLOCKED_AWAITING_INDEPENDENT_AUDIT"
        atomic_write(out / "gate_verdict.json", canonical_bytes(res))
        print(res["gate_decision"])
        return 2
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (ContractError, OSError, json.JSONDecodeError, SyntaxError) as exc:
        print(f"FAIL_CLOSED: {exc}", file=sys.stderr)
        raise SystemExit(2) from None
