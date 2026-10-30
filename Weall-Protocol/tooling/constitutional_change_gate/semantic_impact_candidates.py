#!/usr/bin/env python3
"""Read-only source-to-mechanism/TX/requirement impact candidates for a PR.

This deliberately cannot grant semantic completeness, constitutional authority,
or merge approval. Unmapped/stale paths remain OPEN review obligations.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from collections import Counter, defaultdict
from pathlib import Path, PurePosixPath
from typing import Any

import repository_coverage as coverage

PREFIX = "Weall-Protocol/"
SOURCE_MAP = PREFIX + "generated/v2/source_coverage_map.json"
MECHANISMS = PREFIX + "generated/v2/mechanism_registry.json"
TX_MATRIX = PREFIX + "generated/v2/tx_contract_matrix.json"
REQUIREMENTS = PREFIX + "generated/v2/requirement_traceability.json"
CRITICAL = {
    "consensus_runtime",
    "backend_source",
    "backend_runtime",
    "chain_config",
    "deployment",
    "dependencies",
    "specification",
    "generated",
    "frontend",
    "frontend_build",
    "tooling",
    "ci",
    "repository_control",
}


class ImpactError(ValueError):
    pass


def normalize_v2_path(raw: str) -> str:
    """Resolve draft paths anchored at Weall-Protocol/ without path guessing."""
    if not isinstance(raw, str) or not raw or "\\" in raw or raw.startswith("/"):
        raise ImpactError("unsafe_v2_source_path")
    if raw.startswith(("web/", ".github/", "Weall-Protocol/")):
        parts = []
    else:
        parts = ["Weall-Protocol"]
    for piece in raw.split("/"):
        if piece in ("", "."):
            raise ImpactError("invalid_v2_source_path_component")
        if piece == "..":
            if not parts:
                raise ImpactError("v2_source_path_escape")
            parts.pop()
        else:
            parts.append(piece)
    if not parts or parts[0] not in {"Weall-Protocol", "web", ".github"}:
        raise ImpactError("v2_source_path_outside_authorized_roots")
    return "/".join(parts)


def read_in_commit(repo: Path, commit: str, path: str) -> bytes:
    return coverage.git(repo, "show", f"{commit}:{path}")


def load_json(repo: Path, commit: str, path: str, expected_schema: str | None = None) -> dict:
    try:
        payload = json.loads(read_in_commit(repo, commit, path))
    except (ValueError, UnicodeError) as exc:
        raise ImpactError("invalid_derived_json:" + path) from exc
    if not isinstance(payload, dict):
        raise ImpactError("invalid_derived_object:" + path)
    if expected_schema and payload.get("schema") != expected_schema:
        raise ImpactError("unexpected_derived_schema:" + path)
    return payload


def source_rows(document: dict, *, inventory_paths: set[str]) -> dict[str, dict]:
    rows = document.get("files")
    if not isinstance(rows, list) or document.get("file_count") != len(rows):
        raise ImpactError("source_coverage_cardinality_mismatch")
    if document.get("unmapped_count") != len(document.get("unmapped", [])):
        raise ImpactError("source_coverage_internal_unmapped_mismatch")
    out = {}
    for item in rows:
        if not isinstance(item, dict) or not isinstance(item.get("path"), str):
            raise ImpactError("bad_source_row")
        path = normalize_v2_path(item["path"])
        if path in out:
            raise ImpactError("duplicate_source_path:" + path)
        if path not in inventory_paths:
            raise ImpactError("source_register_ghost_path:" + path)
        ids = item.get("mappings")
        if not isinstance(ids, list) or not all(isinstance(x, str) and x for x in ids):
            raise ImpactError("malformed_source_edges:" + path)
        digest = item.get("sha256")
        if (
            not isinstance(digest, str)
            or len(digest) != 64
            or any(c not in "0123456789abcdef" for c in digest)
        ):
            raise ImpactError("invalid_source_digest:" + path)
        out[path] = item
    return out


def path_candidate_match(path: str, declared: str) -> bool:
    """Only exact files and explicit directory suffixes; never substring guess."""
    if declared.endswith("/"):
        return path.startswith(declared)
    return path == declared


def requirements_index(doc: dict) -> list[dict]:
    rows = doc.get("rows")
    if not isinstance(rows, list) or doc.get("count") != len(rows):
        raise ImpactError("requirements_cardinality_mismatch")
    seen = set()
    normalized = []
    for r in rows:
        if not isinstance(r, dict) or not isinstance(r.get("id"), str) or r["id"] in seen:
            raise ImpactError("duplicate_or_invalid_requirement")
        seen.add(r["id"])
        paths = []
        for p in r.get("implementation_paths", []):
            if not isinstance(p, str):
                raise ImpactError("invalid_requirement_source")
            try:
                # The draft may carry unresolved source paths. Preserve rather
                # than guessing or treating those references as coverage.
                paths.append(normalize_v2_path(p))
            except ImpactError:
                continue
        normalized.append(
            {
                "id": r["id"],
                "paths": paths,
                "contract_ids": [x for x in r.get("contract_ids", []) if isinstance(x, str)],
            }
        )
    return normalized


def semantic_report(repo: Path, base: str, head: str) -> dict[str, Any]:
    if not base:
        raise ImpactError("semantic_review_requires_explicit_base")
    files = coverage.report(repo, base, head)
    if files["coverage_gate"] != "PASS_FILE_CLASSIFICATION_ONLY":
        raise ImpactError("file_inventory_not_fully_classified")
    final_commit = files["source_commit"]
    base_commit = files["base_commit"]
    current_paths = {x["path"] for x in files["files"]}
    previous_paths = {x["path"] for x in coverage.inventory(repo, base_commit)}
    current = source_rows(load_json(repo, final_commit, SOURCE_MAP), inventory_paths=current_paths)
    prior = source_rows(load_json(repo, base_commit, SOURCE_MAP), inventory_paths=previous_paths)
    reg = load_json(repo, final_commit, MECHANISMS)
    if not isinstance(reg.get("rows"), list) or reg.get("count") != len(reg["rows"]):
        raise ImpactError("mechanism_registry_cardinality_mismatch")
    mechanism = {r["id"]: r for r in reg["rows"]}
    if len(mechanism) != len(reg["rows"]):
        raise ImpactError("duplicate_mechanism")
    txs = load_json(repo, final_commit, TX_MATRIX, "weall.v2.tx_contract_matrix")
    if txs.get("transaction_count") != len(txs.get("rows", [])):
        raise ImpactError("tx_matrix_cardinality_mismatch")
    tx_by_id = {x["stable_id"]: x for x in txs["rows"]}
    if len(tx_by_id) != len(txs["rows"]):
        raise ImpactError("tx_stable_id_duplicate")
    reqs = requirements_index(
        load_json(repo, final_commit, REQUIREMENTS, "weall.v2.requirement_traceability")
    )
    entries = []
    for change in files["changes"]:
        impacted = []
        for role, path in (("after", change["path"]), ("before", change["previous_path"])):
            if path is None:
                continue
            exists_in_head = (
                path in current_paths and change["status"][0] != "D" and role == "after"
            )
            relevant = current if exists_in_head else prior
            source = relevant.get(path)
            area = coverage.classify(path)
            if source is None:
                impacted.append(
                    {
                        "side": role,
                        "path": path,
                        "v2_link_status": "NO_DECLARED_SOURCE_EDGE_REVIEW_REQUIRED",
                        "candidate_mechanisms": [],
                        "candidate_txs": [],
                        "candidate_state_or_message_ids": [],
                        "direct_requirement_ids": [],
                        "source_digest_status": "NOT_APPLICABLE_NO_EDGE",
                        "impact_extent": "UNRESOLVED_CONSERVATIVE_SCOPE",
                        "review_priority": "HIGH" if area in CRITICAL else "EVIDENCE_AND_CLAIMS",
                    }
                )
                continue
            ids = sorted(set(source["mappings"]))
            m_ids = [x for x in ids if x.startswith("M-")]
            tx_ids = [x for x in ids if x.startswith("TX-")]
            other_ids = [x for x in ids if x.startswith(("STATE-", "MSG-", "REC-", "FAIL-"))]
            unknown_ids = [x for x in ids if x not in set(m_ids + tx_ids + other_ids)]
            unknown_mechanisms = sorted(set(m_ids) - set(mechanism))
            unknown_txs = sorted(set(tx_ids) - set(tx_by_id))
            if unknown_mechanisms or unknown_txs:
                raise ImpactError("unresolved_v2_edge_ids:" + path)
            pin = "NOT_AVAILABLE_DELETED_PATH"
            if role == "after" and path in current_paths and change["status"][0] != "D":
                actual = hashlib.sha256(read_in_commit(repo, final_commit, path)).hexdigest()
                pin = (
                    "MATCH_EXACT_HEAD_BYTES"
                    if actual == source["sha256"]
                    else "STALE_SHA256_SOURCE_CANDIDATE"
                )
            elif path in previous_paths:
                actual = hashlib.sha256(read_in_commit(repo, base_commit, path)).hexdigest()
                pin = (
                    "MATCH_BASE_BYTES"
                    if actual == source["sha256"]
                    else "STALE_BASE_SOURCE_CANDIDATE"
                )
            req_ids = sorted(
                {
                    req["id"]
                    for req in reqs
                    if any(path_candidate_match(path, q) for q in req["paths"])
                    or (set(req["contract_ids"]) & set(tx_ids))
                }
            )
            impacted.append(
                {
                    "side": role,
                    "path": path,
                    "v2_link_status": "DECLARED_DRAFT_CANDIDATE_UNREVIEWED",
                    "candidate_mechanisms": [
                        {
                            "id": i,
                            "title": mechanism[i].get("title"),
                            "required_evidence": mechanism[i].get("required_evidence", []),
                            "specification_sections": mechanism[i].get(
                                "specification_sections", []
                            ),
                        }
                        for i in m_ids
                    ],
                    "candidate_txs": [
                        {"stable_id": i, "tx_type": tx_by_id[i].get("tx_type")} for i in tx_ids
                    ],
                    "candidate_state_or_message_ids": other_ids,
                    "unrecognized_mapping_ids": unknown_ids,
                    "direct_requirement_ids": req_ids,
                    "source_digest_status": pin,
                    "impact_extent": "DIRECT_CANDIDATES_ONLY_TRANSITIVE_EFFECTS_UNVERIFIED",
                    "review_priority": "HIGH" if area in CRITICAL else "EVIDENCE_AND_CLAIMS",
                }
            )
        entries.append(
            {
                "change": change,
                "candidate_links": impacted,
                "semantic_disposition": "OPEN_UNREVIEWED_POTENTIAL_IMPACT",
                "constitutional_authorization": "NOT_ESTABLISHED",
            }
        )
    missing = sorted(
        {
            r["path"]
            for row in entries
            for r in row["candidate_links"]
            if r["v2_link_status"].startswith("NO_DECLARED")
        }
    )
    stale = sorted(
        {
            r["path"]
            for row in entries
            for r in row["candidate_links"]
            if r["source_digest_status"].startswith("STALE")
        }
    )
    critical_missing = sorted(
        {
            r["path"]
            for row in entries
            for r in row["candidate_links"]
            if r["v2_link_status"].startswith("NO_DECLARED") and r["review_priority"] == "HIGH"
        }
    )
    counts = Counter(
        "DECLARED" if r["v2_link_status"].startswith("DECLARED") else "UNLINKED"
        for row in entries
        for r in row["candidate_links"]
    )
    return {
        "schema": "weall.v2.semantic-impact-review-candidates.v0.1",
        "source_commit": final_commit,
        "comparison_base": base_commit,
        "source_tree": files["source_tree"],
        "file_coverage_report_sha256": files["report_sha256"],
        "source_map_sha256": hashlib.sha256(
            read_in_commit(repo, final_commit, SOURCE_MAP)
        ).hexdigest(),
        "requirements_sha256": hashlib.sha256(
            read_in_commit(repo, final_commit, REQUIREMENTS)
        ).hexdigest(),
        "mechanism_registry_sha256": hashlib.sha256(
            read_in_commit(repo, final_commit, MECHANISMS)
        ).hexdigest(),
        "v2_canonical_tx_count": len(tx_by_id),
        "v2_requirement_count": len(reqs),
        "mechanism_count": len(mechanism),
        "tracked_file_count": files["tracked_file_count"],
        "changed_entry_count": len(entries),
        "reviewed_semantic_edges": 0,
        "candidate_link_observations": dict(counts),
        "unmapped_change_paths": missing,
        "critical_unmapped_change_paths": critical_missing,
        "stale_sha256_source_paths": stale,
        "changes": entries,
        "semantic_review_gate": "BLOCKED_PENDING_TRANSITIVE_TRACING_EXACT_RUNS_AND_INDEPENDENT_ADJUDICATION",
        "normative_authorization": "DRAFT_NOT_ESTABLISHED",
        "note": "Paths, TX labels, mechanism IDs and direct requirement matches are REVIEW CANDIDATES, never evidence that indirect effects are absent.",
    }


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--repo", type=Path, required=True)
    p.add_argument("--base", required=True)
    p.add_argument("--head", required=True)
    p.add_argument("--out", type=Path, required=True)
    args = p.parse_args()
    repo, out = args.repo.resolve(), args.out.resolve()
    if out == repo or repo in out.parents:
        raise ImpactError("output_must_be_outside_checkout")
    result = semantic_report(repo, args.base, args.head)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(
        f"UNREVIEWED_SEMANTIC_CANDIDATES: {result['changed_entry_count']} changes, "
        f"unmapped={len(result['unmapped_change_paths'])}, "
        f"critical_unmapped={len(result['critical_unmapped_change_paths'])}, "
        f"stale={len(result['stale_sha256_source_paths'])}"
    )
    return 0  # Report generation succeeded; this is NOT a merge/release gate pass.


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (ImpactError, coverage.CoverageError, OSError, UnicodeError, ValueError) as exc:
        print(f"SEMANTIC_CANDIDATE_GENERATION_BLOCKED: {exc}")
        raise SystemExit(2) from exc
