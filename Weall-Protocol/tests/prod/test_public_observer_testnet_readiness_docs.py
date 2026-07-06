from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
PLAN = ROOT / "docs" / "audits" / "public_observer_testnet_readiness_plan_v1_5.md"
STATEMENT = ROOT / "docs" / "reviewer" / "CURRENT_TESTNET_READINESS_STATEMENT.md"
BLOCKER_STATUS = ROOT / "docs" / "reviewer" / "PUBLIC_BETA_BLOCKER_STATUS.md"


def _read(path: Path) -> str:
    assert path.exists(), f"missing readiness doc: {path.relative_to(ROOT)}"
    return path.read_text(encoding="utf-8")


def test_public_observer_readiness_plan_defines_bounded_tiers_and_non_claims() -> None:
    text = _read(PLAN)
    assert "Tier A" in text
    assert "Controlled local reviewer testnet" in text
    assert "Tier B" in text
    assert "Public observer testnet" in text
    assert "Tier C" in text
    assert "Controlled validator rehearsal" in text
    assert "Tier D" in text
    assert "Public validator beta / mainnet hardening" in text

    for forbidden_claim in (
        "public beta readiness",
        "public mainnet readiness",
        "public multi-validator BFT readiness",
        "live economics readiness",
        "automatic protocol upgrade readiness",
        "production helper execution readiness",
        "legal/compliance approval",
    ):
        assert forbidden_claim in text

    assert "pre-public-testnet protocol implementation under active hardening" in text.lower()
    assert "public beta readiness still blocked" in text


def test_public_observer_readiness_plan_maps_remaining_blockers_to_evidence() -> None:
    text = _read(PLAN)
    expected = {
        "AUD-618-P0-001": "Independent public validator/operator transcript",
        "AUD-618-P0-002": "Counsel-reviewed attestation",
        "AUD-618-P0-003": "Signed upgrade artifact manifests",
        "AUD-618-P1-003": "External machine or two-physical-machine replay transcript",
        "AUD-618-P1-004": "Real daemon/operator transcript",
        "AUD-618-P1-005": "Production helper enablement gate",
        "AUD-628-P1-001": "External open-download/clean-clone transcript",
    }
    for blocker_id, evidence_phrase in expected.items():
        assert blocker_id in text
        assert evidence_phrase in text


def test_public_observer_readiness_plan_includes_external_transcript_checklist() -> None:
    text = _read(PLAN)
    for required in (
        "operator_name_or_handle",
        "machine_owner",
        "git rev-parse HEAD",
        "python3 -m venv .venv",
        "scripts/check_v15_public_readiness_artifacts.py",
        "scripts/check_release_hygiene_v1_5.py",
        "WEALL_PUBLIC_TESTNET=1 bash scripts/boot_public_observer_testnet.sh",
        "npm run typecheck",
        "npm run build",
        "node scripts/test_rendered_civic_loop_source.mjs",
    ):
        assert required in text
    assert "must not close `AUD-628-P1-001`" in text


def test_current_testnet_readiness_statement_preserves_count_semantics() -> None:
    text = _read(STATEMENT)
    for required in (
        "blocker_catalog_count",
        "closed_in_repository_count",
        "remaining_blocker_count",
        "remaining_external_evidence_required_count",
        "p0_open_count",
        "p1_open_count",
        "public_beta_ready` must remain `false`",
        "AUD-628-P1-001",
        "AUD-618-P1-003",
    ):
        assert required in text
    assert "14" in text
    assert "7" in text


def test_public_beta_blocker_status_points_to_canonical_readiness_docs() -> None:
    text = _read(BLOCKER_STATUS)
    assert "docs/audits/public_observer_testnet_readiness_plan_v1_5.md" in text
    assert "docs/reviewer/CURRENT_TESTNET_READINESS_STATEMENT.md" in text
    assert "Canonical testnet readiness tier mapping" in text
    assert "only an external clean-clone/open-download" in text
