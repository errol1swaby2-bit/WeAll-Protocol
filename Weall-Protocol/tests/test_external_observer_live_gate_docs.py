from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUTER_ROOT = ROOT.parent
WEB_ROOT = OUTER_ROOT / "web"


def test_external_observer_smoke_has_repeatable_live_api_gate() -> None:
    script = (ROOT / "scripts" / "external_observer_onboarding_smoke.sh").read_text(encoding="utf-8")
    assert "WEALL_EXTERNAL_OBSERVER_REQUIRE_LIVE_API" in script
    assert "requires WEALL_GENESIS_API_BASE or WEALL_API_BASE" in script
    assert "/v1/health" in script
    assert "/v1/status" in script
    assert "/v1/ready" in script
    assert "/v1/readyz" in script
    assert "/v1/chain/identity" in script
    assert "/v1/tx/status/external-observer-live-gate-nonexistent-tx" in script
    assert "remote_tx_status_missing_status_field" in script
    assert "remote genesis live API health/ready/status/identity/tx-status checks passed" in script
    assert 'WEALL_VALIDATOR_SIGNING_ENABLED="0"' in script
    assert 'WEALL_BFT_ENABLED="0"' in script
    assert 'WEALL_HELPER_MODE_ENABLED="0"' in script


def test_trusted_external_observer_runbook_documents_live_gate_and_contract_check() -> None:
    doc = (ROOT / "docs" / "TRUSTED_EXTERNAL_OBSERVER_TESTER_RUNBOOK.md").read_text(encoding="utf-8")
    assert "Batch 337 live-gate command sequence" in doc
    assert "WEALL_EXTERNAL_OBSERVER_REQUIRE_LIVE_API=1" in doc
    assert "npm run contract-check" in doc
    assert "npm run production-safety-check" in doc
    assert "/v1/tx/status/:tx_id" in doc
    assert "The first trusted observer is a no-go unless every command above passes" in doc
    assert "observer remains unable to sign validator blocks" in doc


def test_frontend_contract_check_exercises_tx_status_lifecycle() -> None:
    script = (WEB_ROOT / "scripts" / "contract_check.mjs").read_text(encoding="utf-8")
    assert "/v1/tx/status/" in script
    assert "tx status lifecycle status is explicit" in script
    assert "confirmed" in script
    assert "pending" in script
    assert "unknown" in script


def test_frontend_action_lifecycle_copy_distinguishes_recorded_from_done() -> None:
    feedback = (WEB_ROOT / "src" / "lib" / "txFeedback.ts").read_text(encoding="utf-8")
    toast = (WEB_ROOT / "src" / "components" / "TxStatusToast.tsx").read_text(encoding="utf-8")
    card = (WEB_ROOT / "src" / "components" / "ActionLifecycleCard.tsx").read_text(encoding="utf-8")
    assert 'case "recorded":\n      return "Recorded"' in feedback
    assert "Recorded by the backend. Waiting for confirmation or visible state." in toast
    assert "The action is confirmed and visible." in toast
    assert "backend accepted or recorded" in card
    assert "confirmed and visible" in card
