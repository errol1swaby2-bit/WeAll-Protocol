from __future__ import annotations

import json
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
OUTER_ROOT = REPO_ROOT.parent
REGISTRY_PATH = REPO_ROOT / "docs" / "CURRENT_DOCUMENT_REGISTRY.json"

HIGH_RISK_TOP_LEVEL_GLOBS = (
    "Weall-Protocol/docs/*RUNBOOK*.md",
    "Weall-Protocol/docs/*QUICKSTART*.md",
    "Weall-Protocol/docs/*ONBOARDING*.md",
    "Weall-Protocol/docs/runtime_consensus_profile_snapshot_*.md",
)


def _registry() -> dict[str, object]:
    return json.loads(REGISTRY_PATH.read_text(encoding="utf-8"))


def _entries() -> dict[str, dict[str, object]]:
    registry = _registry()
    return {
        str(entry["path"]): entry
        for entry in registry["documents"]  # type: ignore[index]
        if isinstance(entry, dict)
    }


def test_high_risk_top_level_document_families_are_coverage_globs() -> None:
    registry = _registry()
    coverage = set(registry["coverage_globs"])  # type: ignore[arg-type]
    for pattern in HIGH_RISK_TOP_LEVEL_GLOBS:
        assert pattern in coverage


def test_high_risk_top_level_documents_are_explicitly_classified() -> None:
    entries = _entries()
    matched: set[str] = set()

    for pattern in HIGH_RISK_TOP_LEVEL_GLOBS:
        for path in OUTER_ROOT.glob(pattern):
            if not path.is_file():
                continue
            raw = path.relative_to(OUTER_ROOT).as_posix()
            matched.add(raw)
            assert raw in entries, f"unclassified high-risk top-level document: {raw}"

    assert matched, "expected high-risk top-level documentation surfaces"


def test_current_high_risk_operator_docs_are_claim_scanned() -> None:
    entries = _entries()
    for pattern in HIGH_RISK_TOP_LEVEL_GLOBS:
        for path in OUTER_ROOT.glob(pattern):
            if not path.is_file():
                continue
            raw = path.relative_to(OUTER_ROOT).as_posix()
            entry = entries[raw]
            if entry["classification"] == "CURRENT":
                assert entry["claim_scan"] is True, (
                    f"CURRENT high-risk document must opt into claim scanning: {raw}"
                )


def test_superseded_node_operator_pointer_cannot_publish_live_release_truth() -> None:
    entries = _entries()
    raw = "Weall-Protocol/docs/NODE_OPERATOR_ONBOARDING.md"
    entry = entries[raw]
    assert entry["classification"] == "SUPERSEDED"
    assert entry["claim_scan"] is False

    text = (OUTER_ROOT / raw).read_text(encoding="utf-8")
    assert "Status: **SUPERSEDED**" in text
    assert "WEALL_RELEASE_TRUTH_CHECKPOINT_START" not in text
    assert "230 transaction types" not in text
    assert "docs/NEW_NODE_OPERATOR_QUICKSTART.md" in text


def test_runtime_consensus_snapshots_are_historical_only() -> None:
    entries = _entries()
    for name in (
        "runtime_consensus_profile_snapshot_2026-03-prod.4.md",
        "runtime_consensus_profile_snapshot_2026-03-prod.6.md",
    ):
        raw = f"Weall-Protocol/docs/{name}"
        entry = entries[raw]
        assert entry["classification"] == "HISTORICAL"
        assert entry["claim_scan"] is False

        text = (OUTER_ROOT / raw).read_text(encoding="utf-8")
        assert "Status: **HISTORICAL SNAPSHOT**" in text
        assert "WEALL_RELEASE_TRUTH_CHECKPOINT_START" not in text
        assert "Current tx canon checkpoint" not in text


def test_validator_runbook_uses_generated_tx_canon_authority() -> None:
    entries = _entries()
    raw = "Weall-Protocol/docs/PRODUCTION_RUNBOOK_VALIDATORS.md"
    entry = entries[raw]
    assert entry["classification"] == "CURRENT"
    assert entry["claim_scan"] is True

    text = (OUTER_ROOT / raw).read_text(encoding="utf-8")
    assert "generated/tx_index.json" in text
    assert "do not duplicate mutable canon totals" in text
    assert "230 transaction types" not in text
    assert "236 transaction types" not in text
