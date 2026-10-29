#!/usr/bin/env python3
"""Read-only v2 register reconciliation with the canonical TX source and v0.1 gate.

No code, node state, or repository files are modified. Does not confer
constitutional authority, approve a PR, or attest test/reviewer identity.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import re
import stat
from collections import Counter
from pathlib import Path, PurePosixPath
from typing import Any

import weall_change_gate as cg

V2_TX = cg.PREFIX / "generated/v2/tx_contract_matrix.json"
V2_REQUIREMENTS = cg.PREFIX / "generated/v2/requirement_traceability.json"
REVIEWED_PR61 = "d10674253b5fb3cc765ec66442f3eaf5558cb81b"


def normalize_source_path(raw: str) -> str | None:
    """Normalize the existing v2 repo-relative contract paths without guessing roots.

    Prefixes identify only candidate traceability. A valid path never proves
    the implementation is present, correct, or even currently deployed.
    """
    if not isinstance(raw, str) or not raw.strip():
        return None
    s = raw.strip().replace("\\", "/").split("#", 1)[0]
    if not s or s.startswith("/") or re.match(r"^[A-Za-z]:/", s):
        return None
    if s.startswith("../web/"):
        s = s[3:]
    elif s.startswith("Weall-Protocol/") or s.startswith("web/") or s.startswith(".github/"):
        pass
    else:
        s = "Weall-Protocol/" + s
    parts = PurePosixPath(s).parts
    if ".." in parts or "." in parts or not parts:
        return None
    return str(PurePosixPath(*parts))


def path_matches(target: str, candidate: str) -> bool:
    """`candidate` may be a file or directory; never do unbounded substrings."""
    return target == candidate or target.startswith(candidate.rstrip("/") + "/")


def require(condition: bool, msg: str) -> None:
    if not condition:
        raise cg.ContractError(msg)


def authority_review_key(item: dict[str, Any]) -> str:
    """Stable observation identity, independent of candidate report ordering."""
    identity = {
        name: item.get(name)
        for name in (
            "tx_type",
            "state_root",
            "authority_area",
            "source_path",
            "source_function",
            "import_depth",
            "write_signal",
        )
    }
    return "AWC-" + hashlib.sha256(cg.canonical_bytes(identity)).hexdigest()[:24]


MAX_REVIEW_EVIDENCE_BYTES = 64 * 1024 * 1024


def verify_review_evidence_file(
    evidence_root: Path, ref: str, expected_sha256: str
) -> dict[str, Any]:
    """Verify bounded local bytes; no evidence interpretation or attestation."""
    require(
        isinstance(ref, str)
        and 0 < len(ref) <= 1024
        and "\\" not in ref
        and "\0" not in ref
        and not ref.startswith(("/", "~"))
        and re.match(r"^[A-Za-z]:", ref) is None
        and all(component not in {"", ".", ".."} for component in ref.split("/")),
        "review_evidence_ref_unsafe",
    )
    root = evidence_root.resolve(strict=True)
    require(root.is_dir(), "review_evidence_root_not_directory")
    target = root
    for component in ref.split("/"):
        target = target / component
        require(not target.is_symlink(), "review_evidence_symlink_rejected")
    require(target.resolve().is_relative_to(root), "review_evidence_path_outside_root")
    try:
        st = target.stat()
    except (FileNotFoundError, NotADirectoryError):
        raise cg.ContractError("review_evidence_file_missing") from None
    require(stat.S_ISREG(st.st_mode), "review_evidence_not_regular_file")
    require(0 < st.st_size <= MAX_REVIEW_EVIDENCE_BYTES, "review_evidence_size_invalid")
    sha = hashlib.sha256()
    seen = 0
    with target.open("rb") as handle:
        while block := handle.read(1024 * 1024):
            seen += len(block)
            require(seen <= MAX_REVIEW_EVIDENCE_BYTES, "review_evidence_size_invalid")
            sha.update(block)
    require(seen == st.st_size, "review_evidence_size_changed_during_read")
    require(sha.hexdigest() == expected_sha256, "review_evidence_digest_mismatch")
    return {
        "status": "LOCAL_BYTES_SHA256_MATCH_NOT_CONTENT_OR_IDENTITY_ATTESTATION",
        "bytes_read": seen,
        "verified_sha256": sha.hexdigest(),
    }


def reconcile_review_submissions(
    queue: list[dict[str, Any]],
    payload: dict[str, Any] | None,
    checkout_commit: str,
    evidence_root: Path | None = None,
) -> int:
    """Record review claims with optional digest checks, never adjudication.

    Strict binding stops orphan, stale and mismatched metadata from appearing
    on a current queue. Reviewer identity, evidence meaning and constitutional
    authority remain unverified even if local file bytes match a digest.
    """
    if payload is None:
        return 0
    require(
        isinstance(payload, dict)
        and payload.get("schema") == "weall.v2.authority-review-submissions.v0.1"
        and payload.get("source_commit") == checkout_commit
        and isinstance(payload.get("records"), list),
        "invalid_or_stale_review_submission_manifest",
    )
    lookup = {item["review_key"]: item for item in queue}
    seen = set()
    for record in payload["records"]:
        require(isinstance(record, dict), "invalid_review_submission_row")
        key = record.get("review_key")
        require(isinstance(key, str) and key in lookup, "unknown_review_candidate_key")
        require(key not in seen, "duplicate_review_submission")
        seen.add(key)
        item = lookup[key]
        require(
            item["source_file_sha256"] is not None
            and record.get("source_file_sha256") == item["source_file_sha256"],
            "review_submission_source_digest_mismatch",
        )
        require(
            record.get("review_decision")
            in {
                "EFFECT_CLAIMED",
                "NO_EFFECT_CLAIMED",
                "FALSE_POSITIVE_CLAIMED",
                "MORE_EVIDENCE_REQUESTED",
            },
            "unsupported_review_decision",
        )
        require(
            all(
                isinstance(record.get(field), str) and record[field].strip()
                for field in ("reviewer_id", "rationale", "evidence_ref")
            )
            and re.fullmatch(r"[0-9a-f]{64}", str(record.get("evidence_sha256", ""))) is not None,
            "review_submission_metadata_incomplete",
        )
        claimed_reqs = record.get("requirement_ids")
        require(
            isinstance(claimed_reqs, list)
            and all(isinstance(rid, str) for rid in claimed_reqs)
            and len(claimed_reqs) == len(set(claimed_reqs))
            and set(claimed_reqs).issubset(set(item["candidate_requirement_ids"])),
            "review_submission_unmapped_requirement",
        )
        integrity = (
            verify_review_evidence_file(
                evidence_root, record["evidence_ref"], record["evidence_sha256"]
            )
            if evidence_root is not None
            else {"status": "METADATA_ONLY_BYTES_NOT_INSPECTED"}
        )
        item["evidence_byte_integrity"] = integrity
        item["review_submission"] = {
            field: record[field]
            for field in (
                "reviewer_id",
                "review_decision",
                "rationale",
                "evidence_ref",
                "evidence_sha256",
                "requirement_ids",
            )
        }
        item["submission_status"] = "RECORDED_UNAUTHENTICATED_NOT_ADJUDICATED"
        # No record may set reviewed=True, requirements_verified or authorized.
    return len(seen)


def reconcile(
    indexed: dict[str, Any],
    static_rows: dict[str, dict[str, Any]],
    v2_contract: dict[str, Any],
    v2_requirements: dict[str, Any],
    changes: list[str],
    *,
    checkout_commit: str,
    effects: dict[str, Any] | None = None,
    require_effect_pin: bool = False,
    review_submissions: dict[str, Any] | None = None,
    review_evidence_root: Path | None = None,
) -> dict[str, Any]:
    require(
        isinstance(v2_contract, dict)
        and v2_contract.get("schema") == "weall.v2.tx_contract_matrix",
        "v2_tx_schema_unknown",
    )
    require(
        isinstance(v2_requirements, dict)
        and v2_requirements.get("schema") == "weall.v2.requirement_traceability",
        "v2_requirement_schema_unknown",
    )
    txs = v2_contract.get("rows")
    rs = v2_requirements.get("rows")
    require(isinstance(txs, list) and isinstance(rs, list), "v2_missing_rows")
    canon = indexed.get("tx_types")
    require(
        isinstance(canon, list) and isinstance(indexed.get("by_id"), dict),
        "canonical_index_invalid",
    )
    require(v2_contract.get("transaction_count") == len(txs), "v2_tx_count_field_mismatch")
    require(v2_requirements.get("count") == len(rs), "v2_requirement_count_field_mismatch")
    require(
        len({x.get("tx_type") for x in txs if isinstance(x, dict)}) == len(txs),
        "v2_tx_duplicate_or_invalid_names",
    )
    require(
        len({x.get("id") for x in rs if isinstance(x, dict)}) == len(rs),
        "v2_requirement_duplicate_or_invalid_ids",
    )
    tx_by_name = {x["tx_type"]: x for x in txs}
    require(set(tx_by_name) == set(static_rows), "v2_to_code_tx_set_mismatch")
    canonical_names = {x["name"]: x for x in canon}
    require(set(canonical_names) == set(tx_by_name), "v2_canonical_tx_set_mismatch")
    # Numeric indexes live in by_id. The hex `tx_index.tx_types[].id` is a
    # separate identifier and MUST NOT be equated to `numeric_id`.
    by_id = indexed["by_id"]
    numeric_by_name = {canon[pos]["name"]: int(k) for k, pos in by_id.items()}
    require(len(numeric_by_name) == len(canon), "canonical_numeric_id_ambiguous")
    v2_stable_ids = [x.get("stable_id") for x in txs]
    require(
        all(isinstance(x, str) and x for x in v2_stable_ids)
        and len(set(v2_stable_ids)) == len(txs),
        "v2_stable_id_invalid",
    )
    comparisons = []
    for name in sorted(tx_by_name):
        v = tx_by_name[name]
        row = static_rows[name]
        require(
            isinstance(v.get("numeric_id"), int) and v["numeric_id"] == numeric_by_name[name],
            "v2_numeric_id_mismatch:" + name,
        )
        require(v.get("domain") == row["domain"], "v2_domain_mismatch:" + name)
        require(v.get("origin") == row["origin"], "v2_origin_mismatch:" + name)
        require(v.get("context") == row["context"], "v2_context_mismatch:" + name)
        impl = (
            v.get("implementation_source")
            if isinstance(v.get("implementation_source"), dict)
            else {}
        )
        v2_path = normalize_source_path(impl.get("path", ""))
        handler_path = row["source_path"]
        if v2_path == handler_path:
            route_relation = "HANDLER_FILE_MATCH_STATIC_ONLY"
        elif v2_path is None:
            route_relation = "UNRESOLVED_PATH"
        else:
            route_relation = "POSSIBLE_DELEGATE_OR_STALE_PATH_REQUIRES_REVIEW"
        comparisons.append(
            {
                "tx_type": name,
                "canonical_hex_id": row["canonical_id"],
                "numeric_id": v["numeric_id"],
                "v2_stable_id": v["stable_id"],
                "domain": row["domain"],
                "registered_handler": row["handler"],
                "registered_handler_path": handler_path,
                "v2_implementation_path": v2_path,
                "v2_implementation_function": impl.get("function"),
                "route_relation": route_relation,
                "v2_derivation": v.get("semantic_derivation"),
                "v2_independent_review": bool(
                    (v.get("semantic_review") or {}).get("independent_review")
                ),
                "v2_semantic_verification": "NOT_CARRIED_FORWARD_WITHOUT_REPLAY_AND_REVIEW",
                "v2_tests_listed": len(v.get("tests") or []),
            }
        )
    stable_set = set(v2_stable_ids)
    referenced_contract_ids = sorted({str(cid) for x in rs for cid in x.get("contract_ids", [])})
    non_tx_refs = sorted(set(referenced_contract_ids) - stable_set)
    req_with_actual_tx_id = sum(bool(set(r.get("contract_ids", [])) & stable_set) for r in rs)
    normalized_changes = []
    for p in changes:
        if not isinstance(p, str):
            raise cg.ContractError("invalid_changed_path")
        norm = (
            normalize_source_path(p)
            if not p.startswith(("Weall-Protocol/", "web/", ".github/"))
            else p
        )
        if norm is None or PurePosixPath(norm).is_absolute() or ".." in PurePosixPath(norm).parts:
            raise cg.ContractError("unsafe_changed_path:" + p)
        normalized_changes.append(norm)
    change_set = set(normalized_changes)
    by_contract = {v["stable_id"]: v["tx_type"] for v in txs}
    imported_by_tx: dict[str, set[str]] = {name: set() for name in static_rows}
    transitive_by_tx: dict[str, set[str]] = {name: set() for name in static_rows}
    authority_writes_by_tx: dict[str, list[dict[str, Any]]] = {name: [] for name in static_rows}
    if require_effect_pin and effects is None:
        raise cg.ContractError("required_effect_inventory_absent")
    if review_submissions is not None and not require_effect_pin:
        raise cg.ContractError("review_submissions_require_pinned_effects")
    if review_evidence_root is not None and review_submissions is None:
        raise cg.ContractError("review_evidence_root_without_submissions")
    if effects is not None:
        effect_commit = effects.get("source_commit")
        if effect_commit is not None and effect_commit != checkout_commit:
            raise cg.ContractError("effect_source_commit_mismatch")
        if require_effect_pin and (
            effect_commit != checkout_commit
            or (effects.get("source_pin") or {}).get("status")
            != "SCANNED_FILES_TRACKED_AND_CLEAN_AT_HEAD"
        ):
            raise cg.ContractError("effect_source_pin_unverified")
        require(
            isinstance(effects, dict)
            and effects.get("transaction_count") == len(static_rows)
            and isinstance(effects.get("transactions"), list),
            "invalid_effect_candidate_inventory",
        )
        seen_effect_txs: set[str] = set()
        for tx in effects["transactions"]:
            require(isinstance(tx, dict), "invalid_effect_tx_row")
            name = tx.get("tx_type")
            require(isinstance(name, str) and name in static_rows, "unknown_effect_tx_type")
            require(name not in seen_effect_txs, "duplicate_effect_tx_type")
            seen_effect_txs.add(name)
            for item in tx.get("authority_sensitive_write_candidates", []):
                require(isinstance(item, dict), "invalid_authority_write_candidate")
                root = item.get("state_root")
                path = item.get("source_path")
                norm = normalize_source_path(path) if isinstance(path, str) else None
                require(
                    isinstance(root, str)
                    and root in cg.AUTHORITY_REVIEW_ROOTS
                    and item.get("authority_area") == cg.AUTHORITY_REVIEW_ROOTS[root]
                    and norm is not None
                    and norm.startswith("Weall-Protocol/src/weall/runtime/"),
                    "invalid_authority_write_provenance",
                )
                authority_writes_by_tx[name].append({**item, "source_path": norm})
            for item in tx.get("imported_function_candidates", []):
                require(isinstance(item, dict), "invalid_imported_effect_row")
                if item.get("status") != "EXPLICIT_STATE_HANDOFF_IMPORTED_FUNCTION_CANDIDATE":
                    continue
                path = item.get("target_source_path")
                norm = normalize_source_path(path) if isinstance(path, str) else None
                if norm:
                    imported_by_tx[name].add(norm)
            for item in tx.get("transitive_imported_function_candidates", []):
                require(isinstance(item, dict), "invalid_transitive_effect_row")
                if item.get("status") != "TRANSITIVE_EXPLICIT_STATE_HANDOFF_CANDIDATE":
                    continue
                path = item.get("target_source_path")
                norm = normalize_source_path(path) if isinstance(path, str) else None
                if norm:
                    transitive_by_tx[name].add(norm)
        require(seen_effect_txs == set(static_rows), "effect_tx_coverage_mismatch")
    requirement_candidates = []
    for r in rs:
        paths = []
        for raw in r.get("implementation_paths", []):
            norm = normalize_source_path(raw)
            if norm:
                paths.append(norm)
        direct_matches = sorted(
            {p for p in change_set if any(path_matches(p, loc) for loc in paths)}
        )
        explicit_txs = sorted(
            set(by_contract[x] for x in r.get("contract_ids", []) if x in by_contract)
        )
        # A v2 source path can identify a registered handler or a
        # directory containing handlers. Both are UNREVIEWED candidates;
        # neither asserts that the requirement is satisfied or authorized.
        handler_txs = sorted(
            name
            for name, static in static_rows.items()
            if any(path_matches(static["source_path"], loc) for loc in paths)
        )
        imported_effect_txs = sorted(
            name
            for name, observed in imported_by_tx.items()
            if any(path_matches(path, loc) for path in observed for loc in paths)
        )
        transitive_effect_txs = sorted(
            name
            for name, observed in transitive_by_tx.items()
            if any(path_matches(path, loc) for path in observed for loc in paths)
        )
        candidate_txs = sorted(
            set(explicit_txs)
            | set(handler_txs)
            | set(imported_effect_txs)
            | set(transitive_effect_txs)
        )
        if direct_matches:
            category = "SOURCE_PATH_MATCH_REVIEW_CANDIDATE"
        elif explicit_txs:
            category = "CONTRACT_ID_LINK_REVIEW_CANDIDATE"
        elif handler_txs:
            category = "HANDLER_SOURCE_MATCH_REVIEW_CANDIDATE"
        elif imported_effect_txs:
            category = "TRACED_IMPORT_SOURCE_MATCH_REVIEW_CANDIDATE"
        elif transitive_effect_txs:
            category = "TRANSITIVE_IMPORT_SOURCE_MATCH_REVIEW_CANDIDATE"
        else:
            category = "UNLINKED_NOT_SAFE_TO_DISMISS"
        requirement_candidates.append(
            {
                "id": r["id"],
                "title": r.get("title"),
                "section": r.get("section"),
                "status": r.get("status"),
                "verification_result": r.get("verification_result"),
                "reviewer": r.get("reviewer"),
                "implementation_commit": r.get("implementation_commit"),
                "activation_receipt": r.get("activation_receipt"),
                "test_run_id": r.get("test_run_id"),
                "v2_implementation_paths": paths,
                "matching_changed_paths": direct_matches,
                "explicit_canonical_txs": explicit_txs,
                "handler_source_candidate_txs": handler_txs,
                "imported_effect_candidate_txs": imported_effect_txs,
                "transitive_effect_candidate_txs": transitive_effect_txs,
                "candidate_canonical_txs": candidate_txs,
                "contract_refs": r.get("contract_ids", []),
                "candidate_relation": category,
                "link_authority": "UNVERIFIED_SOURCE_PATH_OR_CONTRACT_CANDIDATE_NOT_CONSTITUTIONAL_DECISION",
            }
        )
    # Reverse the many-to-many candidate graph. An empty row is
    # unresolved, not evidence that the TX is unrelated to the requirement.
    reverse: dict[str, list[dict[str, Any]]] = {name: [] for name in static_rows}
    for req in requirement_candidates:
        for name in req["candidate_canonical_txs"]:
            reasons = []
            if name in req["explicit_canonical_txs"]:
                reasons.append("EXPLICIT_V2_ID_UNREVIEWED")
            if name in req["handler_source_candidate_txs"]:
                reasons.append("HANDLER_SOURCE_PATH_UNREVIEWED")
            if name in req["imported_effect_candidate_txs"]:
                reasons.append("TRACED_IMPORT_SOURCE_PATH_UNREVIEWED")
            if name in req["transitive_effect_candidate_txs"]:
                reasons.append("TRANSITIVE_IMPORT_SOURCE_PATH_UNREVIEWED")
            reverse[name].append({"requirement_id": req["id"], "candidate_reasons": reasons})
    # A write-to-requirement edge is supported only by a source-path
    # intersection with that requirement's *declared* implementation paths.
    # The write is a static MAY signal, and the v2 evidence is not accepted
    # as semantic or constitutional proof by this join.
    authority_review_rows: list[dict[str, Any]] = []
    by_requirement = {r["id"]: r for r in requirement_candidates}
    scanned_sha256 = {
        item.get("path"): item.get("sha256")
        for item in (effects or {}).get("source_pin", {}).get("scanned_files", [])
        if isinstance(item, dict)
    }
    for name in sorted(static_rows):
        for effect in authority_writes_by_tx[name]:
            matches = sorted(
                r["id"]
                for r in requirement_candidates
                if any(
                    path_matches(effect["source_path"], req_path)
                    for req_path in r["v2_implementation_paths"]
                )
            )
            review = {
                "tx_type": name,
                "state_root": effect["state_root"],
                "authority_area": effect["authority_area"],
                "source_path": effect["source_path"],
                "source_function": effect.get("source_function"),
                "import_depth": effect.get("import_depth"),
                "write_signal": effect.get("write_signal"),
                "candidate_requirement_ids": matches,
                "candidate_requirement_evidence": [
                    {
                        "requirement_id": rid,
                        "verification_result": by_requirement[rid]["verification_result"],
                        "test_run_id": by_requirement[rid]["test_run_id"],
                        "reviewer": by_requirement[rid]["reviewer"],
                        "implementation_commit": by_requirement[rid]["implementation_commit"],
                        "activation_receipt": by_requirement[rid]["activation_receipt"],
                        "evidence_status": "UNVERIFIED_REQUIREMENT_REFERENCE_NOT_TEST_PROOF",
                    }
                    for rid in matches
                ],
                "unlinked_requirement_review_required": not matches,
                "link_reason": "STATIC_WRITE_SOURCE_PATH_TO_DECLARED_V2_PATH_UNREVIEWED",
                "constitutional_authorization": "NOT_ESTABLISHED",
            }
            authority_review_rows.append(review)
    review_queue_by_key: dict[str, dict[str, Any]] = {}
    for observation in authority_review_rows:
        key = authority_review_key(observation)
        sha = scanned_sha256.get(observation["source_path"])
        if require_effect_pin:
            require(
                isinstance(sha, str) and re.fullmatch(r"[0-9a-f]{64}", sha) is not None,
                "authority_review_source_sha_missing_from_pinned_inventory",
            )
        if key not in review_queue_by_key:
            review_queue_by_key[key] = {
                "review_key": key,
                "source_commit": checkout_commit,
                "source_file_sha256": sha,
                "tx_type": observation["tx_type"],
                "state_root": observation["state_root"],
                "authority_area": observation["authority_area"],
                "source_path": observation["source_path"],
                "source_function": observation["source_function"],
                "import_depth": observation["import_depth"],
                "write_signal": observation["write_signal"],
                "candidate_requirement_ids": observation["candidate_requirement_ids"],
                "triage_bucket": (
                    "NO_DECLARED_V2_REQUIREMENT_PATH_MATCH"
                    if not observation["candidate_requirement_ids"]
                    else "DECLARED_V2_SOURCE_MATCH_UNVERIFIED"
                ),
                "candidate_observation_count": 0,
                "required_review_evidence": [
                    "EXACT_COMMIT_SOURCE_AND_EFFECT_TRACE",
                    "HUMAN_AUTHORITY_AND_REQUIREMENT_ADJUDICATION",
                    "INDEPENDENT_REVIEWER_IDENTITY_VERIFICATION",
                    "REPRODUCIBLE_TARGETED_TEST_AND_LOG",
                    "CONSENSUS_AND_REPLAY_IMPACT_WHEN_APPLICABLE",
                ],
                "submission_status": "OPEN_NO_REVIEW_SUBMISSION",
                "constitutional_authorization": "NOT_ESTABLISHED",
                "review_complete": False,
            }
        review_queue_by_key[key]["candidate_observation_count"] += 1
        observation["review_key"] = key
    authority_review_queue = [review_queue_by_key[key] for key in sorted(review_queue_by_key)]
    submissions_recorded = reconcile_review_submissions(
        authority_review_queue,
        review_submissions,
        checkout_commit,
        evidence_root=review_evidence_root,
    )
    verified_evidence_files = sum(
        q.get("evidence_byte_integrity", {}).get("status")
        == "LOCAL_BYTES_SHA256_MATCH_NOT_CONTENT_OR_IDENTITY_ATTESTATION"
        for q in authority_review_queue
    )
    authority_by_tx: dict[str, list[dict[str, Any]]] = {name: [] for name in static_rows}
    for review in authority_review_rows:
        authority_by_tx[review["tx_type"]].append(review)
    tx_requirement_candidates = [
        {
            "tx_type": name,
            "v2_stable_id": tx_by_name[name]["stable_id"],
            "candidate_requirements": sorted(
                reverse[name], key=lambda link: link["requirement_id"]
            ),
            "candidate_requirement_count": len(reverse[name]),
            "authority_sensitive_write_candidates": authority_by_tx[name],
            "authority_sensitive_write_count": len(authority_by_tx[name]),
            "link_authority": "UNVERIFIED_STATIC_CANDIDATE_ONLY",
        }
        for name in sorted(static_rows)
    ]
    vc_commit = v2_contract.get("provenance", {}).get("implementation_commit")
    vr_commit = v2_requirements.get("provenance", {}).get("implementation_commit")
    require(vc_commit == vr_commit, "v2_derivative_provenance_mismatch")
    v2_pdf = v2_contract.get("provenance", {}).get("normative_pdf_sha256")
    require(
        v2_pdf == v2_requirements.get("provenance", {}).get("normative_pdf_sha256"),
        "v2_derivative_pdf_pin_mismatch",
    )
    status_counts = Counter(r.get("status") for r in rs)
    semantic_counts = Counter(r.get("semantic_derivation") for r in txs)
    src_matches = Counter(x["route_relation"] for x in comparisons)
    candidates = Counter(x["candidate_relation"] for x in requirement_candidates)
    return {
        "schema": "weall.v2.change-impact-reconciliation.v0.2",
        "reconciliation_status": "STRUCTURAL_JOIN_ONLY_NO_MERGE_AUTHORIZATION",
        "target_checkout_commit": checkout_commit,
        "v2_derivative_implementation_commit": vc_commit,
        "v2_source_commit_matches_checkout": vc_commit == checkout_commit,
        "v2_normative_pdf_sha256": v2_pdf,
        "v2_normative_authority_status": v2_contract.get("provenance", {}).get(
            "normative_authority_status"
        ),
        "canonical_tx_count": len(static_rows),
        "v2_tx_count": len(txs),
        "v2_requirement_count": len(rs),
        "canonical_name_domain_origin_context_numeric_join": "MATCHED",
        "tx_independent_review_count": sum(x["v2_independent_review"] for x in comparisons),
        "tx_v2_semantic_derivation_counts": dict(sorted(semantic_counts.items())),
        "tx_implementation_path_relation_counts": dict(sorted(src_matches.items())),
        "requirement_status_counts": dict(sorted(status_counts.items())),
        "requirements_with_realized_test_run": sum(
            r.get("test_run_id") not in (None, "NOT_RUN", "") for r in rs
        ),
        "requirements_with_implementation_commit": sum(
            bool(r.get("implementation_commit")) for r in rs
        ),
        "requirements_with_activation_receipt": sum(bool(r.get("activation_receipt")) for r in rs),
        "requirements_with_explicit_canonical_contract_link": req_with_actual_tx_id,
        "requirements_with_non_tx_contract_refs": sum(
            bool(set(r.get("contract_ids", [])) - stable_set) for r in rs
        ),
        "non_tx_contract_identifiers_not_in_canon": non_tx_refs,
        "requirement_candidate_relation_counts": dict(sorted(candidates.items())),
        "requirements_with_handler_source_tx_candidates": sum(
            bool(req["handler_source_candidate_txs"]) for req in requirement_candidates
        ),
        "requirements_with_imported_effect_candidates": sum(
            bool(req["imported_effect_candidate_txs"]) for req in requirement_candidates
        ),
        "requirements_with_transitive_effect_candidates": sum(
            bool(req["transitive_effect_candidate_txs"]) for req in requirement_candidates
        ),
        "effect_source_pin_status": (
            (effects.get("source_pin") or {}).get("status")
            if effects is not None
            else "NO_EFFECT_INVENTORY"
        ),
        "tx_with_authority_sensitive_write_candidates": sum(
            bool(authority_by_tx[name]) for name in authority_by_tx
        ),
        "authority_sensitive_write_candidate_count": len(authority_review_rows),
        "authority_write_candidates_without_requirement_path_link": sum(
            not row["candidate_requirement_ids"] for row in authority_review_rows
        ),
        "authority_review_queue_item_count": len(authority_review_queue),
        "authority_review_queue_unmatched_count": sum(
            q["triage_bucket"] == "NO_DECLARED_V2_REQUIREMENT_PATH_MATCH"
            for q in authority_review_queue
        ),
        "review_submissions_recorded_unverified": submissions_recorded,
        "review_evidence_files_sha256_checked": verified_evidence_files,
        "review_evidence_submissions_without_byte_checks": (
            submissions_recorded - verified_evidence_files
        ),
        "authority_review_queue_open_count": len(authority_review_queue),
        "independently_authenticated_reviews": 0,
        "tx_with_candidate_requirement_links": sum(
            bool(tx["candidate_requirements"]) for tx in tx_requirement_candidates
        ),
        "tx_requirement_candidate_link_count": sum(
            tx["candidate_requirement_count"] for tx in tx_requirement_candidates
        ),
        "changed_path_count": len(change_set),
        "changed_paths": sorted(change_set),
        "transactions": comparisons,
        "requirements": requirement_candidates,
        "tx_requirement_candidates": tx_requirement_candidates,
        "authority_write_review_candidates": authority_review_rows,
        "authority_review_queue": authority_review_queue,
        "review_submission_schema": "weall.v2.authority-review-submissions.v0.1",
        "not_guaranteed": [
            "Full semantic dependency closure; source paths are a review signal, not a proof",
            "A complete normative requirement-to-TX binding for 755 requirements",
            "Current implementation verified by stale v2 derivative snapshot",
            "Individual test runs, independent reviewer authenticity and activation receipts",
            "Existing persisted ledger replay, live multi-node safety or runtime authorization",
        ],
        "gate": "BLOCKED_PENDING_AUTHORIZED_TRACEABILITY_AND_EXACT_COMMIT_EVIDENCE",
    }


def render_md(out: dict[str, Any]) -> str:
    lines = [
        "# WeAll v2 Register Reconciliation — v0.2",
        "",
        f"**Verdict: {out['gate']}**",
        "",
        f"- Target checkout: `{out['target_checkout_commit']}`",
        f"- v2 matrix implementation snapshot: `{out['v2_derivative_implementation_commit']}`",
        f"- Same commit? **{out['v2_source_commit_matches_checkout']}**",
        f"- Canonical transaction joins: **{out['canonical_name_domain_origin_context_numeric_join']}**, {out['canonical_tx_count']} rows",
        f"- Requirement rows: **{out['v2_requirement_count']}**",
        f"- Independent TX-contract reviews marked complete: **{out['tx_independent_review_count']}**",
        f"- Requirements with recorded test runs: **{out['requirements_with_realized_test_run']}**",
        f"- Requirements with direct canonical TX contract references: **{out['requirements_with_explicit_canonical_contract_link']}**",
        f"- Requirements with handler-source TX candidates: **{out['requirements_with_handler_source_tx_candidates']}**",
        f"- TXs with candidate requirement links: **{out['tx_with_candidate_requirement_links']}**",
        f"- Candidate TX-to-requirement links: **{out['tx_requirement_candidate_link_count']}**",
        f"- Authority-write review queue: **{out['authority_review_queue_item_count']}** unique observations; **{out['authority_review_queue_unmatched_count']}** without declared requirement-source links",
        f"- Review submissions recorded (UNAUTHENTICATED): **{out['review_submissions_recorded_unverified']}**; queue remains OPEN",
        f"- Local evidence SHA-256 checks (NOT attestations): **{out['review_evidence_files_sha256_checked']}**",
        f"- Review claims without byte checks: **{out['review_evidence_submissions_without_byte_checks']}**",
        f"- Non-canonical contract identifiers: **{', '.join(out['non_tx_contract_identifiers_not_in_canon'])}** (not necessarily invalid; these describe mechanisms/schedulers)",
        "",
        "## Requirement selection from actual changed paths",
        "",
        "| Candidate relation | Requirements |",
        "| --- | ---: |",
    ]
    for cat, n in sorted(out["requirement_candidate_relation_counts"].items()):
        lines.append(f"| {cat} | {n} |")
    lines += [
        "",
        "**Caution:** Path-match and identifier-match are evidence-review candidates only. The missing many-to-many authority binding remains unresolved; unlinked requirements cannot be deemed unaffected.",
        "",
        "## Canonical TX source-path differences",
        "",
        "| Relation | TX contracts |",
        "| --- | ---: |",
    ]
    for cat, n in sorted(out["tx_implementation_path_relation_counts"].items()):
        lines.append(f"| {cat} | {n} |")
    lines += [
        "",
        "## Mandatory blockers",
        "",
        "- Normative v2 draft not independently activated as current authority.",
        "- v2 implementation pin is older than the PR #61 target; no evidence inherits automatically.",
        "- Zero recorded requirement test runs and zero independent TX-contract reviews in the parsed v2 matrices.",
        "- Direct contract IDs in v2 requirements currently describe scheduler/mechanism objects, not the 236 canonical TX stable IDs.",
        "- The change-impact matrix must not replace node runtime authorization, deterministic migration or protected-base CI.",
        "- All other requirements remain subject to manual constitutional adjudication; automated inference may omit semantics.",
        "",
    ]
    return "\n".join(lines)


def write_results(doc: dict[str, Any], out: Path) -> None:
    out.mkdir(parents=True, exist_ok=True)
    (out / "v2_reconciliation.json").write_bytes(cg.canonical_bytes(doc))
    (out / "v2_reconciliation.md").write_text(render_md(doc), encoding="utf-8")
    with (out / "v2_tx_join.csv").open("w", newline="", encoding="utf-8") as f:
        keys = [
            "tx_type",
            "canonical_hex_id",
            "numeric_id",
            "v2_stable_id",
            "domain",
            "registered_handler",
            "registered_handler_path",
            "v2_implementation_path",
            "v2_implementation_function",
            "route_relation",
            "v2_derivation",
            "v2_independent_review",
            "v2_semantic_verification",
            "v2_tests_listed",
        ]
        w = csv.DictWriter(f, fieldnames=keys, extrasaction="ignore")
        w.writeheader()
        w.writerows(doc["transactions"])
    with (out / "v2_requirement_impact_candidates.csv").open(
        "w", newline="", encoding="utf-8"
    ) as f:
        keys = [
            "id",
            "title",
            "section",
            "status",
            "verification_result",
            "reviewer",
            "candidate_relation",
            "matching_changed_paths",
            "contract_refs",
            "explicit_canonical_txs",
            "handler_source_candidate_txs",
            "imported_effect_candidate_txs",
            "transitive_effect_candidate_txs",
            "candidate_canonical_txs",
            "implementation_commit",
            "test_run_id",
            "activation_receipt",
        ]
        w = csv.DictWriter(f, fieldnames=keys, extrasaction="ignore")
        w.writeheader()
        for row in doc["requirements"]:
            item = {**row}
            for k in (
                "matching_changed_paths",
                "contract_refs",
                "explicit_canonical_txs",
                "handler_source_candidate_txs",
                "imported_effect_candidate_txs",
                "transitive_effect_candidate_txs",
                "candidate_canonical_txs",
            ):
                item[k] = ";".join(item.get(k) or [])
            w.writerow(item)
    # Separate write-site review ledger; no row constitutes evidence of
    # authorization, semantic impact, or passing tests.
    with (out / "v2_authority_write_review_candidates.csv").open(
        "w", newline="", encoding="utf-8"
    ) as f:
        fields = [
            "tx_type",
            "state_root",
            "authority_area",
            "source_path",
            "source_function",
            "import_depth",
            "write_signal",
            "candidate_requirement_ids",
            "candidate_requirement_test_runs",
            "candidate_requirement_verification",
            "unlinked_requirement_review_required",
            "link_reason",
            "constitutional_authorization",
        ]
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        for item in doc["authority_write_review_candidates"]:
            writer.writerow(
                {
                    **{field: item.get(field) for field in fields},
                    "candidate_requirement_ids": ";".join(item["candidate_requirement_ids"]),
                    "candidate_requirement_test_runs": ";".join(
                        str(x["requirement_id"]) + ":" + str(x["test_run_id"])
                        for x in item["candidate_requirement_evidence"]
                    ),
                    "candidate_requirement_verification": ";".join(
                        str(x["requirement_id"]) + ":" + str(x["verification_result"])
                        for x in item["candidate_requirement_evidence"]
                    ),
                }
            )
    (out / "v2_authority_review_queue.json").write_bytes(
        cg.canonical_bytes(
            {
                "schema": "weall.v2.authority-review-queue.v0.1",
                "source_commit": doc["target_checkout_commit"],
                "review_queue": doc["authority_review_queue"],
                "review_submission_schema": doc["review_submission_schema"],
                "review_submissions_recorded_unverified": doc[
                    "review_submissions_recorded_unverified"
                ],
                "review_evidence_files_sha256_checked": doc["review_evidence_files_sha256_checked"],
                "review_evidence_submissions_without_byte_checks": doc[
                    "review_evidence_submissions_without_byte_checks"
                ],
                "release_authority": "NOT_ESTABLISHED",
            }
        )
    )
    with (out / "v2_authority_review_queue.csv").open("w", newline="", encoding="utf-8") as file:
        columns = [
            "review_key",
            "source_commit",
            "source_file_sha256",
            "tx_type",
            "state_root",
            "authority_area",
            "source_path",
            "source_function",
            "import_depth",
            "write_signal",
            "candidate_requirement_ids",
            "triage_bucket",
            "candidate_observation_count",
            "submission_status",
            "constitutional_authorization",
            "review_complete",
        ]
        writer = csv.DictWriter(file, fieldnames=columns)
        writer.writeheader()
        for item in doc["authority_review_queue"]:
            writer.writerow(
                {
                    **{column: item.get(column) for column in columns},
                    "candidate_requirement_ids": ";".join(item["candidate_requirement_ids"]),
                }
            )
    # Preserve all canonical TXs in the reverse CSV, including TXs with no
    # established candidates. Absence of a link MUST NOT mean unaffected.
    with (out / "v2_tx_requirement_candidates.csv").open("w", newline="", encoding="utf-8") as f:
        fields = [
            "tx_type",
            "v2_stable_id",
            "candidate_requirement_count",
            "candidate_requirement_ids",
            "candidate_reasons",
            "link_authority",
        ]
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        for tx in doc["tx_requirement_candidates"]:
            w.writerow(
                {
                    "tx_type": tx["tx_type"],
                    "v2_stable_id": tx["v2_stable_id"],
                    "candidate_requirement_count": tx["candidate_requirement_count"],
                    "candidate_requirement_ids": ";".join(
                        entry["requirement_id"] for entry in tx["candidate_requirements"]
                    ),
                    "candidate_reasons": ";".join(
                        entry["requirement_id"] + ":" + "|".join(entry["candidate_reasons"])
                        for entry in tx["candidate_requirements"]
                    ),
                    "link_authority": tx["link_authority"],
                }
            )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument(
        "--changed-files-json",
        type=Path,
        default=Path(__file__).resolve().parent / "reference/PR61_changed_files.json",
    )
    parser.add_argument("--expected-head", default=REVIEWED_PR61)
    opts = parser.parse_args(argv)
    repo = opts.repo.resolve()
    out = opts.out.resolve()
    if out == repo or repo in out.parents:
        raise cg.ContractError("output_must_be_outside_repository")
    changes_doc = cg.read_json(opts.changed_files_json)
    require(changes_doc.get("head") == opts.expected_head, "PR_changed_file_manifest_head_mismatch")
    changes = changes_doc.get("changed_files")
    require(
        isinstance(changes, list) and len(changes) > 0 and len(changes) == len(set(changes)),
        "invalid_changed_file_inventory",
    )
    commit = cg.repo_commit(repo)
    require(
        commit == opts.expected_head,
        "checked_out_commit_does_not_match_expected_PR61_head:" + commit,
    )
    actual = cg.git_paths(repo, changes_doc["base"], opts.expected_head)
    require(
        sorted(set(actual)) == sorted(set(changes)),
        "GitHub_observed_PR_diff_and_local_git_diff_disagree",
    )
    rows = cg.extract_routes(repo)
    canon = cg.read_json(repo / cg.INDEX)
    tx = cg.read_json(repo / V2_TX)
    req = cg.read_json(repo / V2_REQUIREMENTS)
    result = reconcile(canon, rows, tx, req, changes, checkout_commit=commit)
    # This is a review report. Never offer an implicit PASS when v2 is stale
    # or normative requirements aren't linked; the underlying v0.1 gate
    # already requires separate independent review and evidence.
    write_results(result, out)
    print(f"REVIEW ONLY: {len(rows)} canonical transactions, {len(req['rows'])} v2 requirements")
    print(f"Output: {out}; {result['gate']}")
    return 2


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (cg.ContractError, OSError, ValueError, KeyError, TypeError) as ex:
        print("FAIL_CLOSED:", ex)
        raise SystemExit(2) from None
