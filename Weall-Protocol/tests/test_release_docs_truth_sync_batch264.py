from __future__ import annotations

import importlib.util
import re
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
OUTER_ROOT = REPO_ROOT.parent


def _load_tx_canon_artifact_constants() -> tuple[int, str]:
    script_path = REPO_ROOT / "scripts" / "check_tx_canon_artifacts.py"
    spec = importlib.util.spec_from_file_location(
        "_weall_check_tx_canon_artifacts_for_docs_test",
        script_path,
    )
    assert spec is not None
    assert spec.loader is not None

    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)

    return int(module.EXPECTED_CANON_COUNT), str(module.EXPECTED_CANON_VERSION)


def _read(path: Path) -> str:
    assert path.exists(), f"missing expected documentation file: {path}"
    return path.read_text(encoding="utf-8")


def test_release_docs_match_current_tx_canon_checkpoint() -> None:
    expected_count, expected_version = _load_tx_canon_artifact_constants()

    docs = [
        OUTER_ROOT / "README.md",
        OUTER_ROOT / "RELEASE_CHECKLIST.md",
        REPO_ROOT / "README.md",
        REPO_ROOT / "docs" / "PRODUCTION_POSTURE.md",
        REPO_ROOT / "docs" / "PROTOCOL_VERSIONING_STRATEGY.md",
        REPO_ROOT / "docs" / "runtime_consensus_profile_snapshot_2026-03-prod.6.md",
    ]

    for path in docs:
        text = _read(path)
        assert str(expected_count) in text, f"{path} does not mention current tx count"
        assert expected_version in text, f"{path} does not mention current tx canon version"


def test_release_docs_state_two_tier_native_poh_without_external_identity_authority() -> None:
    text = "\n\n".join(
        _read(path)
        for path in [
            OUTER_ROOT / "README.md",
            REPO_ROOT / "README.md",
            REPO_ROOT / "docs" / "PRODUCTION_POSTURE.md",
            REPO_ROOT / "docs" / "NODE_OPERATOR_ONBOARDING.md",
        ]
    ).lower()

    assert "tier 1 = native async" in text or "tier 1: native async" in text
    assert "tier 2 = native live" in text or "tier 2: native live" in text
    assert "no required email" in text
    assert "named hosting provider" in text
    assert "no required smtp" in text or "smtp" in text and "not required" in text
    assert "no required dns" in text or "dns" in text and "not required" in text


def test_release_docs_include_current_production_safety_gates() -> None:
    text = "\n\n".join(
        _read(path)
        for path in [
            OUTER_ROOT / "RELEASE_CHECKLIST.md",
            REPO_ROOT / "docs" / "PRODUCTION_POSTURE.md",
            REPO_ROOT / "docs" / "PRODUCTION_RUNBOOK_VALIDATORS.md",
            REPO_ROOT / "docs" / "runtime_consensus_profile_snapshot_2026-03-prod.6.md",
        ]
    ).lower()

    required_phrases = [
        "bft",
        "fail closed",
        "profile-pinned",
        "payload",
        "public api redaction",
        "secret guard",
        "release tree",
    ]

    for phrase in required_phrases:
        assert phrase in text, f"missing release safety phrase: {phrase}"

    snapshot = _read(REPO_ROOT / "docs" / "runtime_consensus_profile_snapshot_2026-03-prod.6.md")
    assert "2026.03-prod.6" in snapshot
    assert re.search(r"\b[a-f0-9]{64}\b", snapshot), "snapshot should include a 64-char profile hash"
