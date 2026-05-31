from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
from typing import Any

from fastapi import APIRouter, HTTPException
from fastapi.responses import JSONResponse

router = APIRouter()

BUNDLE_FILENAME = "weall-external-observer-bundle.json"
MANIFEST_FILENAME = "reviewer-chain-manifest.json"
INDEX_FILENAME = "artifact-index.json"

TRUTH_BOUNDARY = (
    "Disposable reviewer rehearsal artifacts only. These files are public reviewer "
    "support material for a controlled LAN rehearsal. They are not canonical "
    "production Genesis authority, not public mainnet readiness, and not public "
    "multi-validator BFT readiness."
)


def _truthy(value: str | None) -> bool:
    return str(value or "").strip().lower() in {"1", "true", "yes", "y", "on"}


def _enabled() -> bool:
    return _truthy(os.environ.get("WEALL_REVIEWER_ARTIFACTS_ENABLED"))


def _artifact_dir() -> Path:
    raw = str(os.environ.get("WEALL_REVIEWER_ARTIFACTS_DIR") or "").strip()
    if not raw:
        raise HTTPException(status_code=404, detail="reviewer_artifacts_not_configured")
    path = Path(raw).expanduser().resolve()
    if not path.is_dir():
        raise HTTPException(status_code=404, detail="reviewer_artifacts_dir_missing")
    return path


def _require_enabled_dir() -> Path:
    if not _enabled():
        raise HTTPException(status_code=404, detail="reviewer_artifacts_disabled")
    return _artifact_dir()


def _public_file(filename: str) -> Path:
    if filename not in {BUNDLE_FILENAME, MANIFEST_FILENAME, INDEX_FILENAME}:
        raise HTTPException(status_code=404, detail="reviewer_artifact_not_allowed")
    base = _require_enabled_dir()
    path = (base / filename).resolve()
    try:
        path.relative_to(base)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail="reviewer_artifact_path_rejected") from exc
    if not path.is_file():
        raise HTTPException(status_code=404, detail=f"reviewer_artifact_missing:{filename}")
    return path


def _read_json(path: Path) -> dict[str, Any]:
    try:
        obj = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"reviewer_artifact_invalid_json:{path.name}") from exc
    if not isinstance(obj, dict):
        raise HTTPException(status_code=500, detail=f"reviewer_artifact_root_not_object:{path.name}")
    return obj


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _artifact_meta(filename: str, route: str) -> dict[str, Any]:
    path = _public_file(filename)
    return {
        "filename": filename,
        "url": route,
        "bytes": int(path.stat().st_size),
        "sha256": _sha256(path),
    }


@router.get("/reviewer/artifacts")
def reviewer_artifacts_index() -> dict[str, Any]:
    _require_enabled_dir()

    generated_index: dict[str, Any] = {}
    try:
        index_path = _public_file(INDEX_FILENAME)
        generated_index = _read_json(index_path)
    except HTTPException:
        generated_index = {}

    return {
        "ok": True,
        "type": "weall_reviewer_public_artifacts",
        "version": 1,
        "truth_boundary": TRUTH_BOUNDARY,
        "artifacts": {
            "bundle": _artifact_meta(BUNDLE_FILENAME, "/v1/reviewer/artifacts/bundle"),
            "manifest": _artifact_meta(MANIFEST_FILENAME, "/v1/reviewer/artifacts/manifest"),
        },
        "generated_index": generated_index,
    }


@router.get("/reviewer/artifacts/bundle")
def reviewer_artifacts_bundle() -> JSONResponse:
    path = _public_file(BUNDLE_FILENAME)
    return JSONResponse(content=_read_json(path))


@router.get("/reviewer/artifacts/manifest")
def reviewer_artifacts_manifest() -> JSONResponse:
    path = _public_file(MANIFEST_FILENAME)
    return JSONResponse(content=_read_json(path))
