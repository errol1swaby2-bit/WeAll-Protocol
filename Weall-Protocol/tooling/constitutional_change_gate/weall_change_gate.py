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
    args = p.parse_args(argv)
    repo = args.repo.resolve()
    out = args.out.resolve()
    if not (repo / INDEX).is_file():
        raise ContractError("not_a_weall_repo_or_index_missing:" + str(repo))
    if out == repo or repo in out.parents:
        raise ContractError("output_must_be_outside_repository")
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
