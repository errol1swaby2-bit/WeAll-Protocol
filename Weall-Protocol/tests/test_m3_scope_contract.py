from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
BACKEND_ROOT = REPO_ROOT / "Weall-Protocol"
TRACE_PATH = BACKEND_ROOT / "docs/production_readiness/M3_REQUIREMENT_TRACEABILITY.json"
CROSSWALK_PATH = BACKEND_ROOT / "docs/production_readiness/M3_SCOPE_CROSSWALK.json"
TRUTH_PATH = BACKEND_ROOT / "docs/production_readiness/M3_TRUTH_BOUNDARIES.md"
CLOSURE_PATH = BACKEND_ROOT / "docs/production_readiness/M3_CLOSURE_PROCESS.md"
E2E_PATH = REPO_ROOT / "web/tests/e2e/m3_civic_governance_real_stack.spec.ts"
PACKAGE_PATH = REPO_ROOT / "web/package.json"


def _json(path: Path) -> dict[str, object]:
    return json.loads(path.read_text(encoding="utf-8"))


def test_m3_traceability_checker_passes() -> None:
    result = subprocess.run(
        [sys.executable, "scripts/check_m3_requirement_traceability.py"],
        cwd=REPO_ROOT,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
    )
    assert result.returncode == 0, result.stdout
    assert "OK: M3 traceability scaffold validated" in result.stdout


def test_m3_scaffold_records_governance_divergences_as_blockers() -> None:
    trace = _json(TRACE_PATH)
    rows = {
        str(row["id"]): row
        for row in trace["requirements"]  # type: ignore[index]
    }
    for row_id in (
        "M3-P0-01",
        "M3-P0-02",
        "M3-P0-03",
        "M3-P0-04",
        "M3-P0-05",
        "M3-P1-09",
    ):
        assert rows[row_id]["status"] == "open_protocol_gap"

    crosswalk = _json(CROSSWALK_PATH)
    gaps = {
        str(row["mechanism_id"])
        for row in crosswalk["blocking_protocol_gaps"]  # type: ignore[index]
    }
    assert gaps == {"M-050", "M-051"}


def test_m3_docs_preserve_bounded_claim_language() -> None:
    truth = TRUTH_PATH.read_text(encoding="utf-8")
    closure = CLOSURE_PATH.read_text(encoding="utf-8")
    combined = f"{truth}\n{closure}".lower()

    for required in (
        "implementation-freeze commit",
        "evidence-only direct child",
        "first admitted final ballot",
        "frozen denominator",
        "validators are not political principals",
        "public beta",
        "mainnet",
        "emergency governance",
        "r-m1",
    ):
        assert required.lower() in combined

    assert "m3 is closed" not in combined
    assert "production constitutional governance is complete" not in combined


def test_m3_real_stack_skeleton_is_red_and_non_skippable() -> None:
    source = E2E_PATH.read_text(encoding="utf-8")
    package = _json(PACKAGE_PATH)
    scripts = package["scripts"]  # type: ignore[index]

    assert scripts["test:m3-civic-governance-real-stack"] == (
        "playwright test tests/e2e/m3_civic_governance_real_stack.spec.ts"
    )

    for marker in (
        "signed public content",
        "canonical group membership",
        "public report and independent review",
        "appeal and final receipt",
        "frozen electorate",
        "first admitted final ballot",
        "block-height tally and finalization",
        "M3_CLOSURE_NOT_IMPLEMENTED",
    ):
        assert marker in source

    forbidden = (
        "test.skip",
        "test.fixme",
        "load-demo-tester-session",
        "apply_governance(",
        "apply_dispute(",
        "apply_content(",
        "apply_groups(",
    )
    for marker in forbidden:
        assert marker not in source
