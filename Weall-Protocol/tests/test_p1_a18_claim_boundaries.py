from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
CLAIMS_MODULE = ROOT / "scripts" / "gen_current_verified_claims.py"


def _load_claims_module():
    spec = importlib.util.spec_from_file_location("p1_claims_under_test", CLAIMS_MODULE)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _write_matrix(path: Path, *, pending_index: int | None = None) -> None:
    findings = []
    for index in range(34):
        status = "pending_revalidation" if index == pending_index else "patched_and_proven"
        findings.append(
            {
                "id": f"A{index + 1:02d}-F001",
                "severity": "MEDIUM",
                "track": "P1-test",
                "status": status,
                "summary": f"synthetic finding {index + 1}",
            }
        )
    pending = sum(row["status"] == "pending_revalidation" for row in findings)
    path.write_text(
        json.dumps(
            {
                "findings": findings,
                "summary": {
                    "proven_dispositions": 34 - pending,
                    "pending_revalidation": pending,
                },
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )


def test_a18_f004_readme_colocates_poh_status_with_uniqueness_boundary() -> None:
    text = (ROOT / "README.md").read_text(encoding="utf-8")
    marker = "Proof-of-Humanity checkpoint:"
    assert marker in text

    paragraph = text.split(marker, 1)[1].split("\n\n", 1)[0]
    assert "Tier 1 = native async review (compatibility/rehearsal state)" in paragraph
    assert "Tier 2 = native live review (compatibility/rehearsal state)" in paragraph
    assert "scope_closed_pending_uniqueness_entropy" in paragraph
    assert "These tiers are not proof of global one-human uniqueness." in paragraph


def test_a18_f004_readme_does_not_reintroduce_verified_human_shorthand_at_checkpoint() -> None:
    text = (ROOT / "README.md").read_text(encoding="utf-8")
    paragraph = text.split("Proof-of-Humanity checkpoint:", 1)[1].split("\n\n", 1)[0]
    lowered = paragraph.lower()

    assert "verified human" not in lowered
    assert "one-human uniqueness" in lowered


def test_a18_f003_p1_matrix_is_machine_readable_same_tree_claim_input(tmp_path: Path) -> None:
    module = _load_claims_module()
    matrix = tmp_path / "matrix.json"
    _write_matrix(matrix, pending_index=7)

    parsed = module._read_p1_audit_matrix(matrix)

    assert parsed["total_findings"] == 34
    assert parsed["proven_dispositions"] == 33
    assert parsed["open_finding_ids"] == ["A08-F001"]


def test_a18_f003_current_build_exposes_open_p1_findings_and_hashes_matrix() -> None:
    module = _load_claims_module()

    payload = module.build()
    claim = next(row for row in payload["claims"] if row["claim_id"] == "AUDIT-P1-001")

    assert claim["status"] in {
        "OPEN_AUDIT_FINDINGS_BLOCK_STRONGER_CLAIMS",
        "PROVEN_GENERATED_CURRENT",
    }
    assert claim["value"]["total_findings"] == 34
    assert claim["value"]["proven_dispositions"] + len(
        claim["value"]["open_medium_finding_ids"]
    ) == 34
    assert (
        "../audit-metadata/p1-revalidation-after-p0-20261005/MATRIX.json"
        in payload["generation_inputs"]
    )
    if claim["value"]["open_medium_finding_ids"]:
        assert claim["value"]["stronger_release_claims_blocked"] is True
        assert claim["status"] == "OPEN_AUDIT_FINDINGS_BLOCK_STRONGER_CLAIMS"


def test_a18_f003_matrix_summary_drift_fails_closed(tmp_path: Path) -> None:
    module = _load_claims_module()
    matrix = tmp_path / "matrix.json"
    _write_matrix(matrix, pending_index=0)
    obj = json.loads(matrix.read_text(encoding="utf-8"))
    obj["summary"]["proven_dispositions"] = 34
    matrix.write_text(json.dumps(obj, indent=2) + "\n", encoding="utf-8")

    with pytest.raises(SystemExit, match="proven_dispositions disagrees"):
        module._read_p1_audit_matrix(matrix)


def test_a18_f003_unknown_finding_status_fails_closed(tmp_path: Path) -> None:
    module = _load_claims_module()
    matrix = tmp_path / "matrix.json"
    _write_matrix(matrix)
    obj = json.loads(matrix.read_text(encoding="utf-8"))
    obj["findings"][0]["status"] = "looks_good_to_me"
    matrix.write_text(json.dumps(obj, indent=2) + "\n", encoding="utf-8")

    with pytest.raises(SystemExit, match="unrecognized status"):
        module._read_p1_audit_matrix(matrix)
