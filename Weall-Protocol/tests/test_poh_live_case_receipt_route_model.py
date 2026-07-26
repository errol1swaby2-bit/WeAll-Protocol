from __future__ import annotations

from weall.api.routes_public_parts.poh import _as_live_case


def test_live_case_route_model_exposes_receipt_markers() -> None:
    model = _as_live_case(
        "poh_live:@alice:7",
        {
            "account_id": "@alice",
            "status": "awarded",
            "outcome": "pass",
            "tier_awarded": 2,
            "live_receipt_emitted": True,
            "live_receipt_id": "poh_live_rcpt:poh_live:@alice:7",
        },
    )

    assert model.live_receipt_emitted is True
    assert model.live_receipt_id == "poh_live_rcpt:poh_live:@alice:7"


def test_live_case_route_model_defaults_missing_receipt_markers() -> None:
    model = _as_live_case(
        "poh_live:@alice:8",
        {
            "account_id": "@alice",
            "status": "init",
        },
    )

    assert model.live_receipt_emitted is False
    assert model.live_receipt_id is None
