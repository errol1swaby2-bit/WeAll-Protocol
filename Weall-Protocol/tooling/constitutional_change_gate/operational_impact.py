#!/usr/bin/env python3
"""Static candidates for operational paths absent from the v2 source registry.

No shell command is executed. Literal references are *possible* dependencies,
not a sound call graph or permission to approve an operational change.
"""
from __future__ import annotations

import fnmatch
import hashlib
import re
from pathlib import PurePosixPath

import repository_coverage as coverage

MAX_INSPECT_BYTES = 256 * 1024
# Only anchored, literal-looking paths. Expression based dispatch stays open.
LITERAL = re.compile(
    r"(?<![\w/])("
    r"(?:scripts|configs|generated|src/weall|web/src|web/scripts|web/public)"
    r"/[A-Za-z0-9_.\-/]+"
    r"|(?:requirements(?:-dev)?\.(?:in|lock))"
    r")"
)
SCRIPT_DIR = re.compile(
    r"\$\{?SCRIPT_DIR\}?/([A-Za-z0-9_.\-/]+)"
)
ENVIRONMENT = re.compile(
    r"\b(?:WEALL|VITE_WEALL|NODE1|NODE2|REVIEW_COMMIT|GENESIS|OBSERVER)"
    r"_[A-Z0-9_]+\b"
)
STATE_DELETION = re.compile(
    r"(?:^|[;&| \t])rm[ \t]+(?:-[A-Za-z]*[rf]|--recursive|--force)"
)
GENERIC_CODE = re.compile(
    r"(?:^|[;&| \t])(?:bash|sh|exec|source|python3?|docker|git)[ \t]+"
)
DYNAMIC_PATH = re.compile(r"\$\{|\$\(|\$(?:[A-Za-z_])")
HAZARD_TAGS = (
    ("recursive_delete_command_present", STATE_DELETION),
    ("script_or_external_process_invocation_present", GENERIC_CODE),
)


def resolve_candidate(path: str, base: str, known: set[str]) -> str | None:
    """Accept a literal only when its exact resolved Git path exists."""
    if not path or path.startswith("/") or "\\" in path:
        return None
    parts = base.split("/") if base else []
    for bit in path.split("/"):
        if bit in ("", "."):
            continue
        if bit == "..":
            if not parts:
                return None
            parts.pop()
        else:
            parts.append(bit)
    result = "/".join(parts)
    return result if result in known else None


def candidate_mechanisms(path: str, rows: list[dict]) -> list[dict]:
    """Links published in the draft mechanism evidence inventory are hints."""
    matches = []
    for row in rows:
        for declared in row.get("repository_evidence_paths", []):
            if not isinstance(declared, str) or not declared:
                continue
            try:
                if declared.startswith("../"):
                    match_path = resolve_candidate_for_glob(declared, "Weall-Protocol")
                else:
                    match_path = "Weall-Protocol/" + declared
            except ValueError:
                continue
            if fnmatch.fnmatchcase(path, match_path):
                matches.append({"id": row["id"], "source": "DRAFT_MECHANISM_EVIDENCE_PATH"})
                break
    return sorted(matches, key=lambda x: x["id"])


def resolve_candidate_for_glob(relative: str, prefix: str) -> str:
    parts = prefix.split("/")
    for p in relative.split("/"):
        if p == "..":
            if not parts:
                raise ValueError("path escape")
            parts.pop()
        elif p not in (".", ""):
            parts.append(p)
    return "/".join(parts)


def inspect(repo, sha: str, row: dict, inventory: set[str], mechanisms: list[dict]) -> dict:
    path = row["path"]
    area = row["classification"]
    record = {
        "path": path,
        "file_area": area,
        "git_mode": row["git_mode"],
        "git_oid": row["git_oid"],
        "review_status": "OPEN_UNADJUDICATED",
        "possible_dependencies": [],
        "mechanism_evidence_path_candidates": candidate_mechanisms(path, mechanisms),
        "environment_tokens": [],
        "hazard_observations": [],
        "unresolved_observations": [],
    }
    if row["object_type"] != "blob" or row["git_mode"] not in ("100644", "100755"):
        record["scan_status"] = "UNINSPECTED_GIT_OBJECT"
        record["unresolved_observations"].append("GIT_OBJECT_TYPE_REVIEW_REQUIRED")
        return record
    size = int(coverage.git(repo, "cat-file", "-s", row["git_oid"]))
    record["byte_length"] = size
    if size > MAX_INSPECT_BYTES:
        record["scan_status"] = "UNINSPECTED_SIZE_LIMIT"
        record["unresolved_observations"].append("OVERSIZED_OR_BINARY_MANUAL_REVIEW")
        return record
    raw = coverage.git(repo, "show", f"{sha}:{path}")
    record["raw_sha256"] = hashlib.sha256(raw).hexdigest()
    if b"\x00" in raw:
        record["scan_status"] = "UNINSPECTED_BINARY"
        record["unresolved_observations"].append("NON_TEXT_MANUAL_REVIEW")
        return record
    try:
        data = raw.decode("utf-8")
    except UnicodeError:
        record["scan_status"] = "UNINSPECTED_NON_UTF8"
        record["unresolved_observations"].append("NON_TEXT_MANUAL_REVIEW")
        return record
    record["scan_status"] = "STATIC_TEXT_CANDIDATES_ONLY"
    record["environment_tokens"] = sorted(set(ENVIRONMENT.findall(data)))
    record["hazard_observations"] = [
        name for name, detector in HAZARD_TAGS if detector.search(data)
    ]
    if DYNAMIC_PATH.search(data):
        record["unresolved_observations"].append("DYNAMIC_PATH_OR_VARIABLE_USAGE_UNRESOLVED")
    base = "Weall-Protocol" if path.startswith("Weall-Protocol/") else ""
    referenced = set()
    for match in LITERAL.finditer(data):
        token = match.group(1)
        # Resolution is a candidate, not proof that the shell invokes it.
        resolved = resolve_candidate(token, base, inventory)
        if resolved and resolved != path:
            referenced.add(resolved)
    for match in SCRIPT_DIR.finditer(data):
        resolved = resolve_candidate(match.group(1), str(PurePosixPath(path).parent), inventory)
        if resolved and resolved != path:
            referenced.add(resolved)
    record["possible_dependencies"] = sorted(referenced)
    if not referenced and area in {"deployment", "tooling", "chain_config", "dependencies", "specification"}:
        record["unresolved_observations"].append("NO_PROVEN_FILE_DEPENDENCIES")
    # A literal path alone cannot prove the absence of dynamic dependencies.
    record["dependency_completeness"] = "NOT_PROVEN"
    return record


def scan_unlinked(repo, sha: str, file_rows: list[dict], unlinked: list[str], mechanisms: list[dict]) -> dict:
    inventory = {row["path"] for row in file_rows}
    by_path = {row["path"]: row for row in file_rows}
    records = []
    for path in sorted(unlinked):
        if path not in by_path:
            raise ValueError("unlinked_path_not_in_exact_git_tree")
        row = by_path[path]
        if row["classification"] in {"evidence", "documentation"}:
            continue
        records.append(inspect(repo, sha, row, inventory, mechanisms))
    return {
        "status": "UNREVIEWED_STATIC_CANDIDATES_NOT_SEMANTIC_CLOSURE",
        "scanned_priority_file_count": len(records),
        "files": records,
        "files_with_literal_dependency_candidates": sum(bool(x["possible_dependencies"]) for x in records),
        "files_with_destructive_command_observations": sum(
            "recursive_delete_command_present" in x["hazard_observations"] for x in records
        ),
        "manual_review_required": len(records),
    }
