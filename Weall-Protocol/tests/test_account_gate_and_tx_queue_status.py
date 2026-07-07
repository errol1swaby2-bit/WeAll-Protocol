from __future__ import annotations

import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
WEB = ROOT / "web" / "src"


def test_frontend_separates_basic_account_from_posting_eligibility() -> None:
    onboarding = (WEB / "lib" / "onboarding.ts").read_text(encoding="utf-8")
    page = (WEB / "pages" / "AccountVerificationPage.tsx").read_text(encoding="utf-8")

    assert "postingEligible" in onboarding
    assert "const postingEligible =" in onboarding
    assert "tier >= POSTING_MIN_TIER" in onboarding
    assert "const canPost = postingEligible" in onboarding
    assert "Basic account creation is not posting permission" in page
    assert "contentPostingEligible" in page
    assert "Posting eligible" in page
    assert "Live verification needed" in page
    assert "Register basic account" in page
    assert "disabled={!acct || !basicAccountCreated || accountLevel >= 1" in page


def test_onboarding_basic_account_detection_accepts_pubkeys_array() -> None:
    onboarding = (WEB / "lib" / "onboarding.ts").read_text(encoding="utf-8")

    assert "Array.isArray(state.pubkeys)" in onboarding
    assert "state.pubkeys.length > 0" in onboarding


def test_tx_queue_result_compaction_removes_recursive_propagation() -> None:
    from weall.api.routes_public_parts.tx import _compact_tx_queue_result

    nested = {
        "status_reconciliation": [
            {
                "ok": True,
                "status": "confirmed",
                "tx_id": "tx:abc",
                "tx_type": "ACCOUNT_REGISTER",
                "signer": "@errol",
                "height": 1,
                "block_id": "block:1",
                "local_state_synced": True,
                "outbound_propagation": {
                    "last_result": {
                        "status_reconciliation": [
                            {
                                "ok": True,
                                "status": "confirmed",
                                "tx_id": "tx:abc",
                                "outbound_propagation": {"last_result": {"recursive": True}},
                            }
                        ]
                    }
                },
            }
        ]
    }

    compact = _compact_tx_queue_result(nested)
    encoded = json.dumps(compact, sort_keys=True)

    assert compact["status_reconciliation_count"] == 1
    assert compact["status_reconciliation"][0]["tx_id"] == "tx:abc"
    assert compact["status_reconciliation"][0]["tx_type"] == "ACCOUNT_REGISTER"
    assert "outbound_propagation" not in encoded
    assert "recursive" not in encoded
