#!/usr/bin/env python3
"""Candidate repository-wide change inventory and conservative impact routing.

This is an inspectable review gate, not consensus execution, a semantic
call graph, constitutional authorization, or proof of protocol safety.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
from pathlib import Path


class CoverageError(ValueError):
    pass


# Every repository path must match an explicit known class or block. Categories
# are review domains, not claims of harmlessness or semantic completeness.
AREAS = {
    "consensus_runtime": (
        "consensus_replay",
        "state_root_parity",
        "authorization",
        "protocol_tests",
    ),
    "backend_runtime": ("consensus_replay", "state_mutation", "protocol_tests"),
    "backend_source": ("backend_tests", "api_authority", "cross_domain_review"),
    "frontend": ("frontend_build", "browser_real_stack", "api_authority_noninterference"),
    "frontend_build": ("frontend_build", "browser_real_stack", "dependency_audit"),
    "frontend_test": ("browser_real_stack", "test_evidence_integrity"),
    "test": ("test_evidence_integrity", "regression_review"),
    "chain_config": ("chain_identity", "genesis_compatibility", "consensus_replay"),
    "deployment": ("fresh_clone", "restart_catchup", "chain_config_review"),
    "dependencies": ("locked_reproducibility", "dependency_audit", "build_reproduction"),
    "specification": (
        "normative_traceability",
        "constitutional_review",
        "source_derivative_rebuild",
    ),
    "generated": ("source_derivative_rebuild", "artifact_integrity", "protocol_claims_review"),
    "evidence": ("evidence_provenance", "claim_integrity", "independent_review"),
    "tooling": ("test_evidence_integrity", "change_gate_integrity", "reproducibility"),
    "ci": ("workflow_security", "protected_check_review", "release_gate_integrity"),
    "documentation": ("documentation_claim_review", "external_readiness"),
    "repository_control": ("license_security_review", "repository_distribution"),
}


def classify(path: str) -> str | None:
    """Explicit path-domain routing. Unknown paths never receive a safe default."""
    if (
        not path
        or path.startswith("/")
        or "\\" in path
        or any(bit in ("", ".", "..") for bit in path.split("/"))
    ):
        return None
    name = path.rsplit("/", 1)[-1]
    if path.startswith(".github/"):
        return "ci"
    if path.startswith("Weall-Protocol/src/weall/runtime/"):
        return "consensus_runtime"  # conservative: all runtime requires review
    if path.startswith("Weall-Protocol/src/weall/"):
        return "backend_source"
    if path.startswith("Weall-Protocol/tests/"):
        return "test"
    if path.startswith("Weall-Protocol/configs/"):
        return "chain_config"
    if path.startswith("Weall-Protocol/specs/"):
        return "specification"
    if path.startswith("Weall-Protocol/generated/"):
        return "generated"
    if path.startswith("Weall-Protocol/scripts/") or path.startswith("scripts/"):
        return "deployment"
    if path.startswith("Weall-Protocol/tooling/") or path.startswith("tools/"):
        return "tooling"
    if path.startswith("Weall-Protocol/docs/") or path.startswith("docs/"):
        return "documentation"
    if (
        path.startswith("Weall-Protocol/evidence/")
        or path.startswith("Weall-Protocol/artifacts/")
        or path.startswith("artifacts/")
        or path.startswith("audit-metadata/")
    ):
        return "evidence"
    if path.startswith("web/src/generated/"):
        return "generated"
    if path.startswith("web/src/"):
        return "frontend"
    if path.startswith("web/tests/") or path.startswith("web/scripts/"):
        return "frontend_test"
    if path.startswith("web/public/") or path.startswith("web/deploy/"):
        return "deployment"
    if path.startswith("web/"):
        if name in {"package.json", "package-lock.json", "npm-shrinkwrap.json"}:
            return "dependencies"
        return "frontend_build"
    if path.startswith("docker/"):
        return "deployment"
    if path.startswith("Weall-Protocol/"):
        if name.startswith("requirements") or name in {"pyproject.toml", "uv.lock", "poetry.lock"}:
            return "dependencies"
        if name.startswith("docker-compose") or name in {"Dockerfile", "Makefile"}:
            return "deployment"
        if name.endswith((".md", ".txt")) or name in {"LICENSE", "SECURITY"}:
            return "documentation"
        if name.endswith((".sh", ".env.example")) or name.startswith(".env"):
            return "deployment"
        if name in {".gitignore", ".gitattributes"}:
            return "repository_control"
        return None
    if "/" not in path:
        if name.endswith(".sh") or name in {"Dockerfile", "Makefile"}:
            return "deployment"
        if name in {
            ".gitignore",
            ".gitattributes",
            "LICENSE",
            "SECURITY.md",
            "CODE_OF_CONDUCT.md",
            "CONTRIBUTING.md",
        }:
            return "repository_control"
        if name.endswith((".md", ".txt")):
            return "documentation"
    return None


def git(repo: Path, *args: str) -> bytes:
    process = subprocess.run(["git", "-C", str(repo), *args], capture_output=True, check=False)
    if process.returncode:
        raise CoverageError(f"git_error:{args[0]}:{process.stderr.decode(errors='replace')[:240]}")
    return process.stdout


def git_commit(repo: Path, ref: str) -> str:
    sha = git(repo, "rev-parse", "--verify", f"{ref}^{{commit}}").decode().strip()
    if len(sha) != 40 or any(c not in "0123456789abcdef" for c in sha):
        raise CoverageError("invalid_commit_sha")
    return sha


def inventory(repo: Path, head: str) -> list[dict]:
    """Use Git's full recursive tree, not selected source roots or gitignore."""
    payload = git(repo, "ls-tree", "-r", "-z", "--full-tree", head)
    rows = []
    for item in payload.split(b"\x00"):
        if not item:
            continue
        meta, sep, name = item.partition(b"\t")
        parts = meta.decode("ascii").split(" ")
        if not sep or len(parts) != 3:
            raise CoverageError("malformed_tree_entry")
        mode, object_type, oid = parts
        try:
            path = name.decode("utf-8", errors="strict")
        except UnicodeError as exc:
            raise CoverageError("non_utf8_git_path") from exc
        area = classify(path)
        rows.append(
            {
                "path": path,
                "git_mode": mode,
                "object_type": object_type,
                "git_oid": oid,
                "classification": area or "UNCLASSIFIED",
                "review_obligations": list(AREAS.get(area, ("explicit_classification_required",))),
                "coverage": "CLASSIFIED_REVIEW_REQUIRED" if area else "BLOCKED_UNKNOWN_PATH",
            }
        )
    if len(rows) != len({x["path"] for x in rows}):
        raise CoverageError("duplicate_git_paths")
    if not rows:
        raise CoverageError("empty_repository_tree")
    return sorted(rows, key=lambda x: x["path"])


def changed_paths(repo: Path, base: str, head: str) -> list[dict]:
    """Git's diff preserves renames and deletions as first-class observations."""
    payload = git(repo, "diff", "--name-status", "-z", "--find-renames", f"{base}...{head}", "--")
    tokens = [x.decode("utf-8", errors="strict") for x in payload.split(b"\0") if x]
    changes = []
    idx = 0
    while idx < len(tokens):
        status = tokens[idx]
        idx += 1
        allowed = "ACDMRTUXB"
        if not status or status[0] not in allowed:
            raise CoverageError("unknown_git_change_kind")
        if status[0] in ("R", "C"):
            if idx + 1 >= len(tokens):
                raise CoverageError("truncated_rename_or_copy")
            old_path, path = tokens[idx], tokens[idx + 1]
            idx += 2
        else:
            if idx >= len(tokens):
                raise CoverageError("truncated_change_entry")
            old_path, path = None, tokens[idx]
            idx += 1
        paths = [path] + ([old_path] if old_path else [])
        categories = [classify(p) for p in paths]
        obligations = sorted(
            {o for c in categories for o in AREAS.get(c, ("explicit_classification_required",))}
        )
        changes.append(
            {
                "status": status,
                "path": path,
                "previous_path": old_path,
                "classifications": [c or "UNCLASSIFIED" for c in categories],
                "review_obligations": obligations,
                "impact_status": "REVIEW_REQUIRED_UNRESOLVED_SEMANTICS"
                if all(categories)
                else "BLOCKED_UNCLASSIFIED_CHANGE",
            }
        )
    return changes


def report(repo: Path, base: str | None, head: str) -> dict:
    checkout = git_commit(repo, "HEAD")
    expected = git_commit(repo, head)
    if checkout != expected:
        raise CoverageError("head_does_not_match_checkout")
    rows = inventory(repo, expected)
    changes = changed_paths(repo, git_commit(repo, base), expected) if base else []
    classifications = sorted({r["classification"] for r in rows})
    missing = [r["path"] for r in rows if r["coverage"] == "BLOCKED_UNKNOWN_PATH"]
    unknown_changes = [
        c["path"] for c in changes if c["impact_status"] == "BLOCKED_UNCLASSIFIED_CHANGE"
    ]
    body = {
        "schema": "weall.repository-change-coverage.candidate.v1",
        "source_commit": expected,
        "base_commit": git_commit(repo, base) if base else None,
        "source_tree": git(repo, "rev-parse", f"{expected}^{{tree}}").decode().strip(),
        "tracked_file_count": len(rows),
        "classified_file_count": len(rows) - len(missing),
        "unclassified_paths": missing,
        "changed_entry_count": len(changes),
        "unclassified_changed_paths": unknown_changes,
        "classifications_used": classifications,
        "files": rows,
        "changes": changes,
        "semantic_coverage": "NOT_PROVEN_STATIC_ROUTING_REVIEW_REQUIRED",
        "constitutional_authorization": "NOT_ESTABLISHED",
    }
    payload = json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
    body["report_sha256"] = hashlib.sha256(payload).hexdigest()
    body["coverage_gate"] = (
        "PASS_FILE_CLASSIFICATION_ONLY"
        if not missing and not unknown_changes
        else "BLOCKED_UNCLASSIFIED"
    )
    return body


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", type=Path, required=True)
    parser.add_argument("--head", required=True)
    parser.add_argument("--base", default=None)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    repo = args.repo.resolve()
    out = args.out.resolve()
    if out == repo or repo in out.parents:
        raise CoverageError("report_must_be_outside_checkout")
    result = report(repo, args.base, args.head)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(
        f"{result['coverage_gate']}: {result['classified_file_count']}/{result['tracked_file_count']} tracked, {result['changed_entry_count']} changes; SHA256 {result['report_sha256']}"
    )
    return 0 if result["coverage_gate"] == "PASS_FILE_CLASSIFICATION_ONLY" else 2


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (CoverageError, UnicodeError, OSError) as exc:
        print(f"COVERAGE_BLOCKED: {exc}")
        raise SystemExit(2) from exc
