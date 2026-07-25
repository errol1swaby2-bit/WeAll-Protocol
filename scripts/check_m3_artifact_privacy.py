#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any

from m3_evidence_contract import ARTIFACT_ROOT, private_material_findings

ROOT = Path(__file__).resolve().parents[1]


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _scan_file(path: Path) -> list[str]:
    return private_material_findings(path.read_bytes())



def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--artifact-root", default=str(ROOT / ARTIFACT_ROOT))
    parser.add_argument("--out", default="")
    args = parser.parse_args()

    artifact_root = Path(args.artifact_root).expanduser().resolve()
    if not artifact_root.is_dir():
        raise SystemExit(f"m3_artifact_root_missing:{artifact_root}")
    try:
        artifact_root.relative_to(ROOT)
    except ValueError as exc:
        raise SystemExit("m3_artifact_root_must_be_inside_repository") from exc

    out = Path(args.out).expanduser().resolve() if args.out else artifact_root / "privacy/private-material-scan.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    scanned: list[dict[str, Any]] = []
    violations: list[dict[str, Any]] = []
    for path in sorted(p for p in artifact_root.rglob("*") if p.is_file()):
        if path.resolve() == out.resolve():
            continue
        if path.is_symlink():
            violations.append({"path": path.relative_to(ROOT).as_posix(), "findings": ["symlink_forbidden"]})
            continue
        findings = _scan_file(path)
        item = {
            "path": path.relative_to(ROOT).as_posix(),
            "size_bytes": path.stat().st_size,
            "sha256": _sha256(path),
        }
        scanned.append(item)
        if findings:
            violations.append({"path": item["path"], "findings": findings})

    payload = {
        "schema_version": 1,
        "artifact_root": artifact_root.relative_to(ROOT).as_posix(),
        "ok": not violations,
        "files_scanned": len(scanned),
        "violations": violations,
        "scanned_files": scanned,
    }
    out.write_text(json.dumps(payload, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    if violations:
        raise SystemExit("m3_artifact_private_material_detected:" + json.dumps(violations, sort_keys=True))
    print(f"OK: M3 artifact privacy scan passed for {len(scanned)} files")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
