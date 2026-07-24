#!/usr/bin/env python3
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
TRACE = ROOT / "docs" / "production_readiness" / "M2_REQUIREMENT_TRACEABILITY.json"
CROSSWALK = ROOT / "docs" / "production_readiness" / "M2_SCOPE_CROSSWALK.json"
NORMATIVE_REQUIREMENTS = ROOT / "specs" / "v2" / "source" / "requirements.json"
ALLOWED = {"implemented", "implemented_requires_operator_signature_rotation", "evidence_required", "rescoped"}
EXPECTED_DELIVERABLES = {
    "account-custody-e2e",
    "async-poh-e2e",
    "live-poh-e2e",
    "reviewer-queue-runbooks",
    "final-tier-and-gated-action",
}
NORMATIVE_M2_ID = re.compile(r"^(?:ACCT|KEY|POH)-\d{3}$")


def _controlling_normative_ids() -> set[str]:
    payload = json.loads(NORMATIVE_REQUIREMENTS.read_text(encoding="utf-8"))
    rows = payload.get("requirements")
    if not isinstance(rows, list):
        raise SystemExit("m2_normative_requirement_source_missing")
    ids = {
        str(row.get("id") or "").strip()
        for row in rows
        if isinstance(row, dict)
        and NORMATIVE_M2_ID.fullmatch(str(row.get("id") or "").strip())
    }
    if not ids:
        raise SystemExit("m2_normative_requirement_scope_empty")
    return ids


def _list(value: Any, *, label: str) -> list[Any]:
    if not isinstance(value, list):
        raise SystemExit(f"m2_crosswalk_field_not_list:{label}")
    return value


def _validate_paths(values: Any, *, label: str) -> None:
    for raw in _list(values or [], label=label):
        path = ROOT / str(raw)
        if not path.exists():
            raise SystemExit(f"m2_traceability_missing_path:{label}:{raw}")


def main() -> int:
    data = json.loads(TRACE.read_text(encoding="utf-8"))
    rows = data.get("requirements")
    if not isinstance(rows, list) or not rows:
        raise SystemExit("m2_traceability_requirements_missing")
    seen: set[str] = set()
    by_id: dict[str, dict[str, Any]] = {}
    for row in rows:
        if not isinstance(row, dict):
            raise SystemExit("m2_traceability_row_not_object")
        req_id = str(row.get("id") or "").strip()
        if not req_id or req_id in seen:
            raise SystemExit(f"m2_traceability_bad_or_duplicate_id:{req_id}")
        seen.add(req_id)
        by_id[req_id] = row
        status = str(row.get("status") or "").strip()
        if status not in ALLOWED:
            raise SystemExit(f"m2_traceability_bad_status:{req_id}:{status}")
        _validate_paths(row.get("implementation") or [], label=f"{req_id}:implementation")
        _validate_paths(row.get("tests") or [], label=f"{req_id}:tests")
        if status == "evidence_required" and not row.get("evidence"):
            raise SystemExit(f"m2_traceability_evidence_path_missing:{req_id}")

    expected = (
        {f"P0-{i:02d}" for i in range(1, 9)}
        | {f"P1-{i:02d}" for i in range(1, 10)}
        | {f"P2-{i:02d}" for i in range(1, 11)}
    )
    if seen != expected:
        raise SystemExit(
            f"m2_traceability_coverage_mismatch:missing={sorted(expected-seen)}:extra={sorted(seen-expected)}"
        )

    crosswalk = json.loads(CROSSWALK.read_text(encoding="utf-8"))
    deliverables = _list(crosswalk.get("deliverables"), label="deliverables")
    deliverable_ids = {str(item.get("id") or "") for item in deliverables if isinstance(item, dict)}
    if deliverable_ids != EXPECTED_DELIVERABLES:
        raise SystemExit(
            f"m2_crosswalk_deliverable_mismatch:missing={sorted(EXPECTED_DELIVERABLES-deliverable_ids)}:"
            f"extra={sorted(deliverable_ids-EXPECTED_DELIVERABLES)}"
        )

    accounted_normative: set[str] = set()
    for section in ("deliverables", "normative_mappings", "scope_exclusions"):
        for item in _list(crosswalk.get(section), label=section):
            if not isinstance(item, dict):
                raise SystemExit(f"m2_crosswalk_item_not_object:{section}")
            row_ids = [str(value) for value in _list(item.get("requirement_rows") or [], label=f"{section}:rows")]
            for row_id in row_ids:
                if row_id not in by_id:
                    raise SystemExit(f"m2_crosswalk_unknown_requirement_row:{section}:{row_id}")
            if section != "scope_exclusions" and not row_ids:
                raise SystemExit(f"m2_crosswalk_requirement_rows_missing:{section}:{item.get('id')}")
            _validate_paths(item.get("implementation") or [], label=f"{section}:{item.get('id')}:implementation")
            for requirement_id in _list(item.get("requirement_ids") or [], label=f"{section}:requirement_ids"):
                requirement_id = str(requirement_id)
                if requirement_id in accounted_normative:
                    raise SystemExit(f"m2_crosswalk_duplicate_normative_requirement:{requirement_id}")
                accounted_normative.add(requirement_id)

    expected_normative = _controlling_normative_ids()
    if accounted_normative != expected_normative:
        raise SystemExit(
            f"m2_crosswalk_normative_coverage_mismatch:missing={sorted(expected_normative-accounted_normative)}:"
            f"extra={sorted(accounted_normative-expected_normative)}"
        )

    account_custody = next(item for item in deliverables if item.get("id") == "account-custody-e2e")
    if "P2-10" not in account_custody.get("requirement_rows", []):
        raise SystemExit("m2_crosswalk_account_custody_dedicated_row_missing")

    print(
        f"OK: M2 traceability covers {len(rows)} P0/P1/P2 requirements, "
        f"{len(deliverables)} milestone deliverables, and {len(accounted_normative)} ACCT/KEY/POH requirements"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
