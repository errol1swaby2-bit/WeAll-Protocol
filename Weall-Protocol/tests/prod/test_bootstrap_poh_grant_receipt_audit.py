from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def test_production_genesis_bootstrap_grant_is_visible_and_receipt_backed() -> None:
    genesis = json.loads((ROOT / "configs" / "genesis.ledger.prod.json").read_text(encoding="utf-8"))
    accounts = genesis["accounts"]
    founder = accounts["@genesis-founder"]
    grant_id = founder["poh_bootstrap_grant_id"]
    receipt_id = founder["poh_bootstrap_receipt_id"]

    assert founder["poh_tier"] == 2
    assert grant_id.startswith("poh_bootstrap_grant:")
    assert receipt_id.startswith("poh_bootstrap_receipt:")

    grants = genesis["poh"]["bootstrap_grants"]
    grant = grants["by_id"][grant_id]
    assert grant["account_id"] == "@genesis-founder"
    assert grant["grant_type"] == "poh_tier2_live_verified"
    assert grant["authority_path"] in {
        "genesis_bootstrap_profile",
        "production_genesis_manifest",
    }
    assert grant["reason_code"] in {
        "genesis_bootstrap_live",
        "founder_live_bootstrap",
    }
    assert grant["receipt_id"] == receipt_id
    assert grant["auditable"] is True
    assert grant["transitional"] is True
    assert isinstance(grant.get("height", grant.get("grant_height")), int)
    assert grants["by_account"]["@genesis-founder"] == [grant_id]


def test_bootstrap_grant_docs_are_transitional_and_no_tier3() -> None:
    docs = "\n".join(
        path.read_text(encoding="utf-8", errors="ignore")
        for path in [
            ROOT / "docs" / "FIRST_EXTERNAL_OBSERVER_TEST.md",
            ROOT / "docs" / "EXTERNAL_OBSERVER_NODE_REHEARSAL.md",
        ]
        if path.exists()
    )
    assert "transitional" in docs.lower() or "bootstrap" in docs.lower()
    assert "Tier 3" not in docs
    assert "POH_BOOTSTRAP_TIER3_GRANT" not in docs
