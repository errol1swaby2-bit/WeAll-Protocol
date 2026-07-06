from __future__ import annotations

import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
OUTER_ROOT = ROOT.parent
TRACE = ROOT / "docs" / "reviewer" / "README_TO_IMPLEMENTATION_TRACEABILITY.md"
ALLOWED_REHEARSAL_CLAIM = (
    "WeAll is a pre-public-testnet protocol implementation under active hardening, "
    "with local/devnet/public-observer-oriented evidence present and public beta readiness "
    "still blocked by explicit external observer, replay, validator/operator, storage, "
    "legal, upgrade-execution, and helper-topology gates."
)
OPEN_BLOCKERS = {
    "AUD-618-P0-001",
    "AUD-618-P0-002",
    "AUD-618-P0-003",
    "AUD-618-P1-003",
    "AUD-618-P1-004",
    "AUD-618-P1-005",
    "AUD-628-P1-001",
}


def _read(path: Path) -> str:
    assert path.exists(), f"missing expected file: {path}"
    return path.read_text(encoding="utf-8")


def _trace() -> str:
    return _read(TRACE)


def _claim_rows() -> list[str]:
    return [line for line in _trace().splitlines() if re.match(r"\| R-\d{2} \|", line)]


def test_traceability_document_exists_and_is_linked_from_reviewer_entry_points() -> None:
    rel_outer = "Weall-Protocol/docs/reviewer/README_TO_IMPLEMENTATION_TRACEABILITY.md"
    rel_inner = "docs/reviewer/README_TO_IMPLEMENTATION_TRACEABILITY.md"

    assert TRACE.exists()
    assert rel_outer in _read(OUTER_ROOT / "README.md")
    assert "README_TO_IMPLEMENTATION_TRACEABILITY.md" in _read(ROOT / "README.md")
    assert rel_inner in _read(ROOT / "docs" / "reviewer" / "EVIDENCE_INDEX.md")
    assert rel_inner in _read(ROOT / "docs" / "reviewer" / "CURRENT_READINESS_STATEMENT.md")


def test_traceability_preserves_current_claim_boundary_and_forbidden_claims() -> None:
    text = _trace()
    assert ALLOWED_REHEARSAL_CLAIM in text
    for required in (
        "`public_beta_ready` is `false`",
        "Public mainnet readiness is not claimed.",
        "Public multi-validator BFT readiness is not claimed.",
        "Public validator safety is not claimed.",
        "Live economics readiness is not claimed.",
        "Automatic upgrade readiness is not claimed.",
        "Production helper execution readiness is not claimed.",
        "Legal/compliance approval is not claimed.",
        "Public storage-market readiness is not claimed.",
    ):
        assert required in text


def test_traceability_lists_all_remaining_open_blockers() -> None:
    text = _trace()
    for blocker in OPEN_BLOCKERS:
        assert blocker in text
    assert "## Remaining external evidence blockers" in text


def test_traceability_distinguishes_templates_record_only_and_disabled_surfaces() -> None:
    text = _trace()
    for phrase in (
        "Template only",
        "Not completed external evidence",
        "Record only",
        "Disabled by launch gate",
        "Protocol upgrades are record-only",
        "Constitution upgrades are record-only",
        "Live economics is disabled",
        "Production helper execution is disabled",
        "Evidence templates are templates unless accompanied by real external transcript artifacts",
    ):
        assert phrase in text


def test_traceability_contains_required_sections_and_verification_commands() -> None:
    text = _trace()
    for heading in (
        "# README to Implementation Traceability",
        "## Purpose",
        "## Current claim boundary",
        "## Traceability status legend",
        "## README claim map",
        "## Unsupported or narrowed README claims",
        "## Reviewer verification commands",
        "## Remaining external evidence blockers",
    ):
        assert heading in text

    for command in (
        "PYTHONPATH=src:scripts python scripts/gen_public_beta_blocker_report_v1_5.py --check",
        "PYTHONPATH=src python scripts/gen_release_evidence_manifest_v1_5.py --check",
        "PYTHONPATH=src:scripts python scripts/gen_final_public_observer_controlled_testnet_go_gate_v1_5.py --check",
        "PYTHONPATH=src python scripts/check_v15_public_readiness_artifacts.py",
        "PYTHONPATH=src python scripts/check_reviewer_truth_boundaries.py",
        "tests/prod/test_readme_to_implementation_traceability.py",
    ):
        assert command in text


def test_traceability_maps_at_least_forty_readme_claims_with_evidence_or_limitation() -> None:
    rows = _claim_rows()
    assert len(rows) >= 40

    for row in rows:
        cells = [cell.strip() for cell in row.strip().strip("|").split("|")]
        assert len(cells) == 10, row
        claim_id, _readme_claim, _supported_claim, status, implementation, tests, generated, docs, limitation, command = cells
        assert re.fullmatch(r"R-\d{2}", claim_id), row
        assert status, row
        assert limitation, row
        assert command, row
        assert any(field and field != "N/A" for field in (implementation, tests, generated, docs, limitation)), row


def test_traceability_has_no_unbounded_risky_readiness_phrases() -> None:
    text = _trace().lower()
    unsafe_phrases = [
        "weall is public beta ready",
        "weall is mainnet ready",
        "weall is production ready",
        "public validators are safe",
        "automatic upgrades are ready",
        "live economics are ready",
        "legally approved",
        "decentralized storage ready",
        "public storage market ready",
    ]
    findings = [phrase for phrase in unsafe_phrases if phrase in text]
    assert findings == []
