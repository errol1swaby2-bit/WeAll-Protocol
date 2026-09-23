#!/usr/bin/env python3
from __future__ import annotations

import json
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
PROTOCOL_ROOT = REPO_ROOT / "Weall-Protocol"

MAPPING_PATHS = {
    "scripts/bootstrap_r20_remediation.py",
    "scripts/patch_r20_materialized_drivers.py",
}
EXCLUDED_GENERATED = {
    "generated/r20_remaining_remediation_result.json",
    "generated/r20_remediation_driver_result.json",
    "generated/r20_repository_description_action.txt",
    "generated/r20_semantic_review_rebind.json",
    "generated/r20_stale_semantic_reviews.json",
}
REMOVE_PROTOCOL = {
    "scripts/bootstrap_r20_remediation.py",
    "scripts/patch_r20_materialized_drivers.py",
    "scripts/r20_driver_a.py.gz.b64",
    "scripts/r20_driver_b.py.gz.b64",
    "generated/r20_remediation_driver_result.json",
    "generated/r20_remaining_remediation_result.json",
    "generated/r20_comprehensive_remediation_coverage.json",
    "generated/r20_repository_description_action.txt",
    "generated/r20_stale_semantic_reviews.json",
    "generated/r20_semantic_review_rebind.json",
    "generated/r20_driver_a.log",
    "generated/r20_driver_b.log",
}
REMOVE_REPO = {
    ".github/workflows/r20-comprehensive-remediation.yml",
    ".github/r20/rebind_semantic_reviews.py",
    ".github/r20/finalize_candidate.py",
}


def main() -> int:
    mappings_path = PROTOCOL_ROOT / "specs" / "v2" / "source" / "source_mappings.json"
    payload = json.loads(mappings_path.read_text(encoding="utf-8"))

    mappings = payload.get("mappings")
    if not isinstance(mappings, list):
        raise SystemExit("source_mappings.json mappings must be a list")
    existing_mapping_paths = {
        str(row.get("path") or "")
        for row in mappings
        if isinstance(row, dict)
    }
    missing_mapping_paths = sorted(MAPPING_PATHS - existing_mapping_paths)
    if missing_mapping_paths:
        raise SystemExit(f"expected r20 tooling mappings missing before cleanup: {missing_mapping_paths}")
    payload["mappings"] = [
        row
        for row in mappings
        if not (isinstance(row, dict) and str(row.get("path") or "") in MAPPING_PATHS)
    ]

    exclusions = payload.get("excluded_local_artifacts")
    if not isinstance(exclusions, list):
        raise SystemExit("source_mappings.json excluded_local_artifacts must be a list")
    existing_exclusions = {
        str(row.get("path") or "")
        for row in exclusions
        if isinstance(row, dict)
    }
    missing_exclusions = sorted(EXCLUDED_GENERATED - existing_exclusions)
    if missing_exclusions:
        raise SystemExit(f"expected r20 generated exclusions missing before cleanup: {missing_exclusions}")
    payload["excluded_local_artifacts"] = [
        row
        for row in exclusions
        if not (
            isinstance(row, dict)
            and str(row.get("path") or "") in EXCLUDED_GENERATED
        )
    ]

    mappings_path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")

    required = {
        PROTOCOL_ROOT / "scripts" / "bootstrap_r20_remediation.py",
        PROTOCOL_ROOT / "scripts" / "patch_r20_materialized_drivers.py",
        REPO_ROOT / ".github" / "workflows" / "r20-comprehensive-remediation.yml",
    }
    missing_required = sorted(str(path.relative_to(REPO_ROOT)) for path in required if not path.exists())
    if missing_required:
        raise SystemExit(f"expected remediation-only files missing before cleanup: {missing_required}")

    removed: list[str] = []
    for rel in sorted(REMOVE_PROTOCOL):
        path = PROTOCOL_ROOT / rel
        if path.exists():
            path.unlink()
            removed.append(str(path.relative_to(REPO_ROOT)))
    for rel in sorted(REMOVE_REPO):
        path = REPO_ROOT / rel
        if path.exists():
            path.unlink()
            removed.append(str(path.relative_to(REPO_ROOT)))

    print(json.dumps({
        "removed_count": len(removed),
        "removed": removed,
        "source_mapping_cleanup": {
            "removed_exact_tooling_mappings": sorted(MAPPING_PATHS),
            "removed_generated_exclusions": sorted(EXCLUDED_GENERATED),
        },
    }, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
