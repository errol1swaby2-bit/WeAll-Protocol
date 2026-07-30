#!/usr/bin/env python3
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
BACKEND = ROOT / "Weall-Protocol"
TRACE_PATH = BACKEND / "docs/production_readiness/M3_REQUIREMENT_TRACEABILITY.json"
CROSSWALK_PATH = BACKEND / "docs/production_readiness/M3_SCOPE_CROSSWALK.json"
MANIFEST_PATH = ROOT / "artifacts/m3-closure/M3_EVIDENCE_MANIFEST.json"

REQUIRED_MECHANISMS = {
    "M-039",
    "M-040",
    "M-041",
    "M-042",
    "M-043",
    "M-049",
    "M-050",
    "M-051",
    "M-054",
    "M-055",
    "M-056",
}

REQUIRED_REQUIREMENTS = {
    "M3-P0-01",
    "M3-P0-02",
    "M3-P0-03",
    "M3-P0-04",
    "M3-P0-05",
    "M3-P0-06",
    "M3-P0-07",
    "M3-P1-01",
    "M3-P1-02",
    "M3-P1-03",
    "M3-P1-04",
    "M3-P1-05",
    "M3-P1-06",
    "M3-P1-07",
    "M3-P1-08",
    "M3-P1-09",
    "M3-P1-10",
    "M3-P2-01",
    "M3-P2-02",
    "M3-P2-03",
    "M3-P2-04",
    "M3-P2-05",
    "M3-P2-06",
    "M3-P2-07",
}

REQUIRED_DELIVERABLES = {
    "m3-governance-corrections",
    "m3-content-group-e2e",
    "m3-dispute-appeal-e2e",
    "m3-proposal-finalization-e2e",
    "m3-determinism",
    "m3-closure-integrity",
}

REQUIRED_EXCLUSIONS = {"M-045", "M-052", "M-053", "M-058"}
REQUIRED_BLOCKING_GAPS: set[str] = set()


class ContractError(RuntimeError):
    pass


def _load(path: Path) -> dict[str, Any]:
    if not path.is_file():
        raise ContractError(f"m3_traceability_missing:{path.relative_to(ROOT)}")
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        raise ContractError(f"m3_traceability_invalid_json:{path.relative_to(ROOT)}:{exc}") from exc
    if not isinstance(value, dict):
        raise ContractError(f"m3_traceability_not_object:{path.relative_to(ROOT)}")
    return value


def _manifest_evidence_paths() -> set[str]:
    manifest = _load(MANIFEST_PATH)
    if manifest.get("schema_version") != 3:
        raise ContractError("m3_evidence_manifest_schema_version")
    files = manifest.get("files")
    if not isinstance(files, list) or not files:
        raise ContractError("m3_evidence_manifest_files_not_list")

    declared: set[str] = {str(MANIFEST_PATH.relative_to(ROOT)).replace("\\", "/")}
    for item in files:
        if not isinstance(item, dict):
            raise ContractError("m3_evidence_manifest_file_not_object")
        evidence_path = str(item.get("path") or "").strip().rstrip("/")
        if not evidence_path.startswith("artifacts/m3-closure/"):
            raise ContractError(f"m3_evidence_manifest_path_outside_root:{evidence_path}")
        declared.add(evidence_path)
    return declared


def _strings(value: Any, *, field: str, row_id: str) -> list[str]:
    if not isinstance(value, list) or not value:
        raise ContractError(f"m3_traceability_missing_list:{row_id}:{field}")
    out: list[str] = []
    for item in value:
        text = str(item or "").strip()
        if not text:
            raise ContractError(f"m3_traceability_blank_list_item:{row_id}:{field}")
        out.append(text)
    return out


def _resolve_repository_path(value: str) -> Path:
    text = str(value or "").strip()
    if text.startswith("../"):
        return (BACKEND / text).resolve()
    if text.startswith(("Weall-Protocol/", "web/", "artifacts/", ".github/")):
        return (ROOT / text).resolve()
    if text.startswith("scripts/"):
        root_candidate = (ROOT / text).resolve()
        backend_candidate = (BACKEND / text).resolve()
        if root_candidate.exists():
            return root_candidate
        return backend_candidate
    return (BACKEND / text).resolve()


def _require_paths_exist(values: list[str], *, field: str, row_id: str) -> int:
    checked = 0
    for value in values:
        path = _resolve_repository_path(value)
        try:
            path.relative_to(ROOT)
        except ValueError as exc:
            raise ContractError(
                f"m3_traceability_path_outside_repository:{row_id}:{field}:{value}"
            ) from exc
        if not path.exists():
            raise ContractError(f"m3_traceability_path_missing:{row_id}:{field}:{value}")
        if path.is_symlink():
            raise ContractError(f"m3_traceability_symlink_forbidden:{row_id}:{field}:{value}")
        checked += 1
    return checked


def _require_evidence_paths_declared(
    values: list[str],
    *,
    field: str,
    row_id: str,
    manifest_paths: set[str],
) -> int:
    checked = 0
    for value in values:
        normalized = value.strip().rstrip("/")
        if not normalized.startswith("artifacts/m3-closure/"):
            raise ContractError(
                f"m3_traceability_evidence_outside_artifact_root:{row_id}:{field}:{value}"
            )

        exact = normalized in manifest_paths
        prefix = normalized + "/"
        contains_bound_artifact = any(
            evidence_path.startswith(prefix) for evidence_path in manifest_paths
        )
        if not exact and not contains_bound_artifact:
            raise ContractError(
                f"m3_traceability_evidence_not_manifest_bound:{row_id}:{field}:{value}"
            )

        repository_path = _resolve_repository_path(normalized)
        if repository_path.exists() and repository_path.is_symlink():
            raise ContractError(f"m3_traceability_symlink_forbidden:{row_id}:{field}:{value}")
        checked += 1
    return checked


def main() -> int:
    trace = _load(TRACE_PATH)
    crosswalk = _load(CROSSWALK_PATH)
    manifest_paths = _manifest_evidence_paths()

    if trace.get("schema_version") != 1 or crosswalk.get("schema_version") != 1:
        raise ContractError("m3_traceability_schema_version")

    if "R-M3" not in str(trace.get("milestone") or ""):
        raise ContractError("m3_traceability_wrong_milestone")
    if "R-M3" not in str(crosswalk.get("milestone") or ""):
        raise ContractError("m3_crosswalk_wrong_milestone")

    controlled = {str(item) for item in trace.get("controlled_statuses", []) if str(item).strip()}
    if not controlled:
        raise ContractError("m3_traceability_missing_controlled_statuses")

    raw_rows = trace.get("requirements")
    if not isinstance(raw_rows, list):
        raise ContractError("m3_traceability_requirements_not_list")

    rows: dict[str, dict[str, Any]] = {}
    mechanism_union: set[str] = set()
    checked_paths = 0
    for raw in raw_rows:
        if not isinstance(raw, dict):
            raise ContractError("m3_traceability_requirement_not_object")
        row_id = str(raw.get("id") or "").strip()
        if not row_id:
            raise ContractError("m3_traceability_requirement_missing_id")
        if row_id in rows:
            raise ContractError(f"m3_traceability_duplicate_requirement:{row_id}")
        rows[row_id] = raw

        title = str(raw.get("title") or "").strip()
        acceptance = str(raw.get("acceptance") or "").strip()
        priority = str(raw.get("priority") or "").strip()
        status = str(raw.get("status") or "").strip()

        if not title:
            raise ContractError(f"m3_traceability_missing_title:{row_id}")
        if not acceptance:
            raise ContractError(f"m3_traceability_missing_acceptance:{row_id}")
        if priority not in {"P0", "P1", "P2"}:
            raise ContractError(f"m3_traceability_invalid_priority:{row_id}:{priority}")
        if status not in controlled:
            raise ContractError(f"m3_traceability_uncontrolled_status:{row_id}:{status}")

        mechanisms = set(_strings(raw.get("mechanisms"), field="mechanisms", row_id=row_id))
        unknown = mechanisms - REQUIRED_MECHANISMS
        if unknown:
            raise ContractError(
                f"m3_traceability_unknown_mechanisms:{row_id}:{','.join(sorted(unknown))}"
            )
        mechanism_union.update(mechanisms)

        implementation_paths = _strings(
            raw.get("implementation"), field="implementation", row_id=row_id
        )
        test_paths = _strings(raw.get("tests"), field="tests", row_id=row_id)
        checked_paths += _require_paths_exist(
            implementation_paths, field="implementation", row_id=row_id
        )
        checked_paths += _require_paths_exist(test_paths, field="tests", row_id=row_id)

        evidence_paths = _strings(
            raw.get("evidence"),
            field="evidence",
            row_id=row_id,
        )
        checked_paths += _require_evidence_paths_declared(
            evidence_paths,
            field="evidence",
            row_id=row_id,
            manifest_paths=manifest_paths,
        )

    found_requirements = set(rows)
    if found_requirements != REQUIRED_REQUIREMENTS:
        raise ContractError(
            "m3_traceability_requirement_set_mismatch:"
            + json.dumps(
                {
                    "missing": sorted(REQUIRED_REQUIREMENTS - found_requirements),
                    "unexpected": sorted(found_requirements - REQUIRED_REQUIREMENTS),
                },
                sort_keys=True,
            )
        )

    if mechanism_union != REQUIRED_MECHANISMS:
        raise ContractError(
            "m3_traceability_mechanism_coverage_mismatch:"
            + json.dumps(
                {
                    "missing": sorted(REQUIRED_MECHANISMS - mechanism_union),
                    "unexpected": sorted(mechanism_union - REQUIRED_MECHANISMS),
                },
                sort_keys=True,
            )
        )

    non_closed_rows = sorted(
        row_id for row_id, row in rows.items() if row.get("status") != "closed"
    )
    if non_closed_rows:
        raise ContractError("m3_traceability_requirement_not_closed:" + ",".join(non_closed_rows))

    mechanism_rows = crosswalk.get("mechanism_scope")
    if not isinstance(mechanism_rows, list):
        raise ContractError("m3_crosswalk_mechanism_scope_not_list")
    cross_mechanisms = {
        str(item.get("id") or "").strip() for item in mechanism_rows if isinstance(item, dict)
    }
    if cross_mechanisms != REQUIRED_MECHANISMS:
        raise ContractError(
            "m3_crosswalk_mechanism_set_mismatch:"
            + json.dumps(
                {
                    "missing": sorted(REQUIRED_MECHANISMS - cross_mechanisms),
                    "unexpected": sorted(cross_mechanisms - REQUIRED_MECHANISMS),
                },
                sort_keys=True,
            )
        )

    deliverables = crosswalk.get("deliverables")
    if not isinstance(deliverables, list):
        raise ContractError("m3_crosswalk_deliverables_not_list")
    deliverable_ids = {
        str(item.get("id") or "").strip() for item in deliverables if isinstance(item, dict)
    }
    if deliverable_ids != REQUIRED_DELIVERABLES:
        raise ContractError(
            "m3_crosswalk_deliverable_set_mismatch:"
            + json.dumps(
                {
                    "missing": sorted(REQUIRED_DELIVERABLES - deliverable_ids),
                    "unexpected": sorted(deliverable_ids - REQUIRED_DELIVERABLES),
                },
                sort_keys=True,
            )
        )

    for item in deliverables:
        if not isinstance(item, dict):
            raise ContractError("m3_crosswalk_deliverable_not_object")
        deliverable_id = str(item.get("id") or "").strip()
        implementation_paths = _strings(
            item.get("implementation"), field="implementation", row_id=deliverable_id
        )
        checked_paths += _require_paths_exist(
            implementation_paths,
            field="implementation",
            row_id=deliverable_id,
        )
        evidence_paths = _strings(
            item.get("evidence"),
            field="evidence",
            row_id=deliverable_id,
        )
        checked_paths += _require_evidence_paths_declared(
            evidence_paths,
            field="evidence",
            row_id=deliverable_id,
            manifest_paths=manifest_paths,
        )
        if item.get("status") != "closed":
            raise ContractError(f"m3_crosswalk_deliverable_not_closed:{deliverable_id}")

    corrections = crosswalk.get("implemented_protocol_corrections")
    if not isinstance(corrections, list):
        raise ContractError("m3_crosswalk_corrections_not_list")
    for item in corrections:
        if not isinstance(item, dict):
            raise ContractError("m3_crosswalk_correction_not_object")
        correction_id = str(item.get("id") or "").strip()
        verification = _strings(
            item.get("verification"),
            field="verification",
            row_id=correction_id,
        )
        repository_paths = [value for value in verification if not value.startswith("artifacts/")]
        evidence_paths = [value for value in verification if value.startswith("artifacts/")]
        checked_paths += _require_paths_exist(
            repository_paths,
            field="verification",
            row_id=correction_id,
        )
        checked_paths += _require_evidence_paths_declared(
            evidence_paths,
            field="verification",
            row_id=correction_id,
            manifest_paths=manifest_paths,
        )

    gaps = crosswalk.get("blocking_protocol_gaps")
    if not isinstance(gaps, list):
        raise ContractError("m3_crosswalk_blocking_gaps_not_list")
    gap_ids = {str(item.get("id") or "").strip() for item in gaps if isinstance(item, dict)}
    if gap_ids != REQUIRED_BLOCKING_GAPS:
        raise ContractError(
            "m3_crosswalk_blocking_gap_set_mismatch:"
            + json.dumps(
                {
                    "missing": sorted(REQUIRED_BLOCKING_GAPS - gap_ids),
                    "unexpected": sorted(gap_ids - REQUIRED_BLOCKING_GAPS),
                },
                sort_keys=True,
            )
        )

    exclusions = crosswalk.get("scope_exclusions")
    if not isinstance(exclusions, list):
        raise ContractError("m3_crosswalk_exclusions_not_list")
    excluded_mechanisms = {
        str(item.get("mechanism_id") or "").strip()
        for item in exclusions
        if isinstance(item, dict) and item.get("mechanism_id")
    }
    if not REQUIRED_EXCLUSIONS.issubset(excluded_mechanisms):
        raise ContractError(
            "m3_crosswalk_missing_exclusions:"
            + ",".join(sorted(REQUIRED_EXCLUSIONS - excluded_mechanisms))
        )
    if REQUIRED_MECHANISMS.intersection(excluded_mechanisms):
        raise ContractError("m3_crosswalk_scoped_mechanism_excluded")

    print(
        "OK: M3 traceability validated "
        f"{len(rows)} requirements, "
        f"{len(cross_mechanisms)} mechanisms, "
        f"{len(deliverable_ids)} deliverables, "
        f"{checked_paths} repository paths, and "
        f"{len(gap_ids)} blocking protocol gaps"
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except ContractError as exc:
        print(str(exc))
        raise SystemExit(1) from exc
