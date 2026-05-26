from __future__ import annotations

"""Source-controlled WeAll Genesis Constitution commitments.

This module intentionally does not interpret constitutional rights.  It exposes
stable commitments that chain manifests, status endpoints, and tests can use to
prove which constitutional document a node is claiming to run under.
"""

from pathlib import Path
from typing import Any, Mapping

from weall.runtime.chain_manifest import sha256_hex

Json = dict[str, Any]

CONSTITUTION_VERSION = "draft-2"
CONSTITUTION_DOC_RELATIVE_PATH = "docs/constitution/WEALL_GENESIS_CONSTITUTION_DRAFT_2.md"
CONSTITUTION_TRACEABILITY_RELATIVE_PATH = "docs/constitution/CONSTITUTIONAL_TRACEABILITY.md"


def repo_root() -> Path:
    return Path(__file__).resolve().parents[3]


def constitution_doc_path() -> Path:
    return repo_root() / CONSTITUTION_DOC_RELATIVE_PATH


def constitution_traceability_path() -> Path:
    return repo_root() / CONSTITUTION_TRACEABILITY_RELATIVE_PATH


def constitution_document_hash() -> str:
    return sha256_hex(constitution_doc_path().read_bytes())


def constitution_traceability_hash() -> str:
    return sha256_hex(constitution_traceability_path().read_bytes())


def manifest_constitution_commitment(raw: Mapping[str, Any] | None) -> Json:
    obj = dict(raw or {})
    nested = obj.get("constitution") if isinstance(obj.get("constitution"), Mapping) else {}
    return {
        "version": str(obj.get("constitution_version") or nested.get("version") or "").strip(),
        "hash": str(obj.get("constitution_hash") or nested.get("hash") or "").strip().lower(),
        "document_path": str(obj.get("constitution_document_path") or nested.get("document_path") or CONSTITUTION_DOC_RELATIVE_PATH).strip(),
        "traceability_hash": str(obj.get("constitution_traceability_hash") or nested.get("traceability_hash") or "").strip().lower(),
    }


def active_constitution_commitment(raw_manifest: Mapping[str, Any] | None = None) -> Json:
    manifest = manifest_constitution_commitment(raw_manifest)
    doc_hash = constitution_document_hash()
    trace_hash = constitution_traceability_hash()
    version = manifest["version"] or CONSTITUTION_VERSION
    claimed_hash = manifest["hash"] or doc_hash
    claimed_trace = manifest["traceability_hash"] or trace_hash
    return {
        "version": version,
        "hash": claimed_hash,
        "document_hash": doc_hash,
        "document_path": manifest["document_path"] or CONSTITUTION_DOC_RELATIVE_PATH,
        "traceability_hash": claimed_trace,
        "active": bool(version and claimed_hash and claimed_hash == doc_hash),
        "hash_matches_source": bool(claimed_hash and claimed_hash == doc_hash),
        "traceability_hash_matches_source": bool(claimed_trace and claimed_trace == trace_hash),
        "status": "genesis_bound" if claimed_hash == doc_hash and version else "unbound_or_mismatch",
    }
